/*++

Copyright (c) 1992  Microsoft Corporation

Module Name:

    spti.c

Abstract:

    Win32 application that can communicate directly with SCSI devices via
    IOCTLs.

Author:


Environment:

    User mode.

Notes:


Revision History:

--*/

#include <windows.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <strsafe.h>
#include <intsafe.h>
#define _NTSCSI_USER_MODE_
#include <scsi.h>
#include "spti.h"

#define NAME_COUNT  25

#define BOOLEAN_TO_STRING(_b_) \
( (_b_) ? "True" : "False" )

#if defined(_X86_)
    #define PAGE_SIZE  0x1000
    #define PAGE_SHIFT 12L
#elif defined(_AMD64_)
    #define PAGE_SIZE  0x1000
    #define PAGE_SHIFT 12L
#elif defined(_IA64_)
    #define PAGE_SIZE 0x2000
    #define PAGE_SHIFT 13L
#else
    // undefined platform?
    #define PAGE_SIZE  0x1000
    #define PAGE_SHIFT 12L
#endif


LPCSTR BusTypeStrings[] = {
    "Unknown",
    "Scsi",
    "Atapi",
    "Ata",
    "1394",
    "Ssa",
    "Fibre",
    "Usb",
    "RAID",
    "Not Defined",
};
#define NUMBER_OF_BUS_TYPE_STRINGS (sizeof(BusTypeStrings)/sizeof(BusTypeStrings[0]))


typedef struct {
    int disk_number;     // --disk
    int is_write;        // --write flag
    int is_read;         // --read flag
    unsigned long lba;   // --lba 
    unsigned int sector_cnt; // --sector_cnt
    unsigned char data_pattern; // --data
} CommandLineArgs;

void print_usage(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  --disk <number>      Select disk number\n");
    printf("  --write             Perform write operation\n");
    printf("  --read              Perform read operation\n");
    printf("  --lba <address>     Specify starting logical block address\n");
    printf("  --sector_cnt <count> Specify number of sectors to operate on\n");
    printf("  --data <pattern>    Specify hex pattern to write (e.g., FF)\n");
    printf("\nExamples:\n");
    printf("  %s --disk 0 --write --lba 0 --sector_cnt 1 --data FF\n", program_name);
    printf("  %s --disk 1 --read --lba 100 --sector_cnt 10\n", program_name);
}

int parse_arguments(int argc, char* argv[], CommandLineArgs* args) {
    memset(args, 0, sizeof(CommandLineArgs));
    args->disk_number = -1; // Invalid disk number by default

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--disk") == 0) {
            if (++i >= argc) {
                printf("Error: --disk requires a number\n");
                return 0;
            }
            args->disk_number = atoi(argv[i]);
            if (args->disk_number < 0) {
                printf("Error: Invalid disk number\n");
                return 0;
            }
        }
        else if (strcmp(argv[i], "--write") == 0) {
            args->is_write = 1;
        }
        else if (strcmp(argv[i], "--read") == 0) {
            args->is_read = 1;
        }
        else if (strcmp(argv[i], "--lba") == 0) {
            if (++i >= argc) {
                printf("Error: --lba requires a value\n");
                return 0;
            }
            args->lba = strtoul(argv[i], NULL, 0);
        }
        else if (strcmp(argv[i], "--sector_cnt") == 0) {
            if (++i >= argc) {
                printf("Error: --sector_cnt requires a value\n");
                return 0;
            }
            args->sector_cnt = (unsigned int)strtoul(argv[i], NULL, 0);
        }
        else if (strcmp(argv[i], "--data") == 0) {
            if (++i >= argc) {
                printf("Error: --data requires a hex value\n");
                return 0;
            }
            unsigned int temp;
            if (sscanf(argv[i], "%x", &temp) != 1) {
                printf("Error: Invalid hex value for --data\n");
                return 0;
            }
            args->data_pattern = (unsigned char)temp;
        }
        else {
            printf("Error: Unknown option: %s\n", argv[i]);
            return 0;
        }
    }

    // Validate arguments
    if (args->disk_number == -1) {
        printf("Error: --disk is required\n");
        return 0;
    }

    if (!(args->is_read || args->is_write)) {
        printf("Error: Either --read or --write must be specified\n");
        return 0;
    }

    if (args->is_read && args->is_write) {
        printf("Error: Cannot specify both --read and --write\n");
        return 0;
    }

    if (args->is_write && args->data_pattern == 0 && !argv[1]) {
        printf("Warning: No data pattern specified for write operation, using 0x00\n");
    }

    if (args->sector_cnt == 0) {
        printf("Error: --sector_cnt must be greater than 0\n");
        return 0;
    }

    return 1;
}

BOOL GetDiskPath(int diskNumber, LPSTR devicePath, size_t devicePathSize) {
    if (sprintf_s(devicePath, devicePathSize, "\\\\.\\PhysicalDrive%d", diskNumber) < 0) {
        return FALSE;
    }
    return TRUE;
}

void PerformWrite(HANDLE fileHandle, CommandLineArgs* args, ULONG alignmentMask) {
    PUCHAR dataBuffer = NULL;
    PUCHAR pUnAlignedBuffer = NULL;
    DWORD returned = 0;
    const DWORD SECTOR_SIZE = 512;
    BOOL status = FALSE;

    printf("\n*********************************************** start write ****************************************************\n");
    printf("disk: %d\n", args->disk_number);
    printf("LBA start: %lu\n", args->lba);
    printf("sector_cnt: %u\n", args->sector_cnt);
    printf("data pattern: 0x%02X\n", args->data_pattern);

    // 1. �]�m�ö�R�w�İ�
    DWORD bufferSize = args->sector_cnt * SECTOR_SIZE;
    dataBuffer = AllocateAlignedBuffer(bufferSize, alignmentMask, &pUnAlignedBuffer);

    if (!dataBuffer) {
        printf("Error�Gcan't allocate memory!\n");
        return;
    }


    // �Ϋ��w���Ҧ���R�w�İ�
    memset(dataBuffer, args->data_pattern, bufferSize);

    // 2. �]�m SCSI Pass Through Direct ���c
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb = { 0 };

    sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptdwb.sptd.PathId = 0;
    sptdwb.sptd.TargetId = 0;  // �����X�ݺϺ�
    sptdwb.sptd.Lun = 0;

    sptdwb.sptd.CdbLength = 16;  // WRITE(16)
    sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_OUT;  // �g�J�ާ@
    sptdwb.sptd.DataTransferLength = bufferSize;
    sptdwb.sptd.TimeOutValue = 60;  // �W�[�W�ɮɶ�
    sptdwb.sptd.DataBuffer = dataBuffer;

    sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
    sptdwb.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);

    // �]�m WRITE(16) CDB
    sptdwb.sptd.Cdb[0] = 0x8A;     // WRITE(16) �ާ@�X
    sptdwb.sptd.Cdb[1] = 0x00;     // �g�J�ﶵ

    // 64-bit LBA - �����]�m���쬰 0 �]���w��W�欰2048LBA �ҥH32bits�w����
    sptdwb.sptd.Cdb[2] = 0x00;    // LBA [63:56]
    sptdwb.sptd.Cdb[3] = 0x00;    // LBA [55:48]
    sptdwb.sptd.Cdb[4] = 0x00;    // LBA [47:40]
    sptdwb.sptd.Cdb[5] = 0x00;    // LBA [39:32]

    sptdwb.sptd.Cdb[6] = (UCHAR)(args->lba >> 24);  // LBA [31:24]
    sptdwb.sptd.Cdb[7] = (UCHAR)(args->lba >> 16);  // LBA [23:16]
    sptdwb.sptd.Cdb[8] = (UCHAR)(args->lba >> 8);   // LBA [15:8]
    sptdwb.sptd.Cdb[9] = (UCHAR)(args->lba);        // LBA [7:0]

    // �]�m�ǿ���ס]���ϼơ^
    sptdwb.sptd.Cdb[10] = (UCHAR)(args->sector_cnt >> 24);
    sptdwb.sptd.Cdb[11] = (UCHAR)(args->sector_cnt >> 16);
    sptdwb.sptd.Cdb[12] = (UCHAR)(args->sector_cnt >> 8);
    sptdwb.sptd.Cdb[13] = (UCHAR)(args->sector_cnt);

    sptdwb.sptd.Cdb[14] = 0x00;  // Reserved
    sptdwb.sptd.Cdb[15] = 0x00;  // Control

    // 3. ���� SCSI �R�O
    status = DeviceIoControl(fileHandle,
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        &sptdwb,
        sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
        &sptdwb,
        sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
        &returned,
        NULL);

    // 4. 檢查執行結果
    if (!status) {
        printf("DeviceIoControl failed, error code: %lu\n", GetLastError());
        printf("Write failed, please turn off write protection.\n");
        /*PrintError(GetLastError());*/
    }
    else if (sptdwb.sptd.ScsiStatus != 0) {
        printf("SCSI Command Failed, SCSI Status: %02Xh\n", sptdwb.sptd.ScsiStatus);
        PrintSenseInfo((PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb);
    }
    else {
        printf("\nWrite data completed (LBA: %u to %u)\n",
            args->lba, args->lba + args->sector_cnt - 1);
        printf("Pattern: 0x%02X\n", args->data_pattern);
        printf("Total bytes written: %lu\n", bufferSize);
        printf("Done!\n");
    }

    // 5. 清理資源
    if (pUnAlignedBuffer) {
        free(pUnAlignedBuffer);
    }
    printf("\n*********************************************** write end ****************************************************\n");
}
void PerformRead(HANDLE fileHandle, CommandLineArgs* args, ULONG alignmentMask) {
    printf("\n*********************************************** start read ****************************************************\n");
    // �ϥΤw����� fileHandle �M alignmentMask
    PUCHAR dataBuffer = NULL;
    PUCHAR pUnAlignedBuffer = NULL;
    DWORD returned = 0;
    const DWORD SECTOR_SIZE = 512;
    BOOL status = FALSE;

    printf("disk: %d\n", args->disk_number);
    printf("LBA start: %lu\n", args->lba);
    printf("sector_cnt: %u\n", args->sector_cnt);

    // 1. ���t������w�İ� (sector_cnt * 512 bytes)
    DWORD bufferSize = args->sector_cnt * SECTOR_SIZE;
    dataBuffer = AllocateAlignedBuffer(bufferSize, alignmentMask, &pUnAlignedBuffer);

    if (!dataBuffer) {
        printf("Error�Gcan't allocate memory!\n");
        return;
    }

    // 2. �]�m SCSI Pass Through Direct ���c
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb = { 0 };

    sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptdwb.sptd.PathId = 0;     // 0:�Ĥ@�Ӹ��|
    sptdwb.sptd.TargetId = 0;   // 0:�����X�ݺϺ�
    sptdwb.sptd.Lun = 0;        // �޿�椸���A�q�` 0

    sptdwb.sptd.CdbLength = 16;  // Read(16)
    sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_IN;
    sptdwb.sptd.DataTransferLength = bufferSize;
    sptdwb.sptd.TimeOutValue = 60;  // �W�[�W�ɮɶ��H�B�z�j�q�ƾ�
    sptdwb.sptd.DataBuffer = dataBuffer;

    sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
    sptdwb.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);

    // READ(16) CDB �]�m
    sptdwb.sptd.Cdb[0] = 0x88;     // READ(16) �ާ@�X
    sptdwb.sptd.Cdb[1] = 0x00;
    // �]�m 64-bit LBA 
    //sptdwb.sptd.Cdb[2] = (UCHAR)(args->lba >> 56);  // LBA [63:56]
    //sptdwb.sptd.Cdb[3] = (UCHAR)(args->lba >> 48);  // LBA [55:48]
    //sptdwb.sptd.Cdb[4] = (UCHAR)(args->lba >> 40);  // LBA [47:40]
    //sptdwb.sptd.Cdb[5] = (UCHAR)(args->lba >> 32);  // LBA [39:32]
    sptdwb.sptd.Cdb[2] = 0x00;     // LBA [63:56]
    sptdwb.sptd.Cdb[3] = 0x00;     // LBA [55:48]
    sptdwb.sptd.Cdb[4] = 0x00;     // LBA [47:40]
    sptdwb.sptd.Cdb[5] = 0x00;     // LBA [39:32]
    sptdwb.sptd.Cdb[6] = (UCHAR)(args->lba >> 24);  // LBA [31:24]
    sptdwb.sptd.Cdb[7] = (UCHAR)(args->lba >> 16);  // LBA [23:16]
    sptdwb.sptd.Cdb[8] = (UCHAR)(args->lba >> 8);   // LBA [15:8]
    sptdwb.sptd.Cdb[9] = (UCHAR)(args->lba);        // LBA [7:0]

    // �]�m 32-bit Transfer Length
    sptdwb.sptd.Cdb[10] = (UCHAR)(args->sector_cnt >> 24);  // Length [31:24]
    sptdwb.sptd.Cdb[11] = (UCHAR)(args->sector_cnt >> 16);  // Length [23:16]
    sptdwb.sptd.Cdb[12] = (UCHAR)(args->sector_cnt >> 8);   // Length [15:8]
    sptdwb.sptd.Cdb[13] = (UCHAR)(args->sector_cnt);        // Length [7:0]

    // ��l�줸�եi�]�� 0
    sptdwb.sptd.Cdb[14] = 0x00;  // Reserved
    sptdwb.sptd.Cdb[15] = 0x00;  // Control

    // 4. ���� SCSI �R�O
    status = DeviceIoControl(fileHandle,
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        &sptdwb,
        sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
        &sptdwb,
        sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
        &returned,
        NULL);

    // 5. �ˬd���浲�G
    if (!status) {
        printf("DeviceIoControl ����, ���~�X: %lu\n", GetLastError());
        PrintError(GetLastError());
    }
    else if (sptdwb.sptd.ScsiStatus != 0) {
        printf("SCSI �R�O���楢��, SCSI ���A: %02Xh\n", sptdwb.sptd.ScsiStatus);
        PrintSenseInfo((PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb);
        // ��ܧ��㪺 sense data
        for (ULONG i = 0; i < SPT_SENSE_LENGTH; i++) {
            printf("%02X ", sptdwb.ucSenseBuf[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");

        // �ѪR sense data
        if (sptdwb.ucSenseBuf[0] == 0x70 || sptdwb.ucSenseBuf[0] == 0x71) {
            UCHAR senseKey = sptdwb.ucSenseBuf[2] & 0x0F;
            UCHAR asc = sptdwb.ucSenseBuf[12];
            UCHAR ascq = sptdwb.ucSenseBuf[13];

            printf("Sense Key: %02Xh - ", senseKey);
            switch (senseKey) {
            case 0x0: printf("No Sense\n"); break;
            case 0x1: printf("Recovered Error\n"); break;
            case 0x2: printf("Not Ready\n"); break;
            case 0x3: printf("Medium Error\n"); break;
            case 0x4: printf("Hardware Error\n"); break;
            case 0x5: printf("Illegal Request\n"); break;
            case 0x6: printf("Unit Attention\n"); break;
            case 0x7: printf("Data Protect\n"); break;
            case 0x8: printf("Blank Check\n"); break;
            case 0x9: printf("Vendor Specific\n"); break;
            case 0xA: printf("Copy Aborted\n"); break;
            case 0xB: printf("Aborted Command\n"); break;
            case 0xC: printf("Equal\n"); break;
            case 0xD: printf("Volume Overflow\n"); break;
            case 0xE: printf("Miscompare\n"); break;
            case 0xF: printf("Completed\n"); break;
            default: printf("Unknown\n"); break;
            }

            printf("Additional Sense Code (ASC): %02Xh\n", asc);
            printf("Additional Sense Code Qualifier (ASCQ): %02Xh\n", ascq);
        }
    }
    else {
        // ���\Ū���A��ܼƾ�
        printf("\nRead data�G\n");
        PrintDataBuffer(dataBuffer, bufferSize);
    }

    // 6. �M�z�귽
    if (pUnAlignedBuffer) {
        free(pUnAlignedBuffer);
    }
    printf("\n*********************************************** read end ****************************************************\n");
}


VOID
__cdecl
main(
    _In_ int argc,
    _In_z_ char *argv[]
    )

{
    CommandLineArgs args;
    BOOL status = 0;
    DWORD accessMode = 0, shareMode = 0;
    HANDLE fileHandle = NULL;
    ULONG alignmentMask = 0; // default == no alignment requirement
    UCHAR srbType = 0; // default == SRB_TYPE_SCSI_REQUEST_BLOCK
    PUCHAR dataBuffer = NULL;
    PUCHAR pUnAlignedBuffer = NULL;
    SCSI_PASS_THROUGH_WITH_BUFFERS sptwb;
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb;
    SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex;
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX sptdwb_ex;
    //CHAR string[NAME_COUNT];
    CHAR devicePath[MAX_PATH];

    ULONG length = 0,
          errorCode = 0,
          returned = 0,
          sectorSize = 512;
    

    if (!parse_arguments(argc, argv, &args)) {
        print_usage(argv[0]);
        return;
    }

    if ((argc < 2) || (argc > 3)) {
       printf("Usage:  %s <port-name> [-mode]\n", argv[0] );
       printf("Examples:\n");
       printf("    spti g:       (open the disk class driver in SHARED READ/WRITE mode)\n");
       printf("    spti Scsi2:   (open the miniport driver for the 3rd host adapter)\n");
       printf("    spti Tape0 w  (open the tape class driver in SHARED WRITE mode)\n");
       printf("    spti i: c     (open the CD-ROM class driver in SHARED READ mode)\n");
       return;
    }

    //StringCbPrintf(string, sizeof(string), "\\\\.\\%s", argv[1]);

    shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;  // default
    accessMode = GENERIC_WRITE | GENERIC_READ;       // default

    if (args.is_read) {
        shareMode = FILE_SHARE_READ;
    }
    else if (args.is_write) {
        shareMode = FILE_SHARE_WRITE;
    }
    if (!GetDiskPath(args.disk_number, devicePath, sizeof(devicePath))) {
        fputs("Error creating device path for disk", stderr);
        //printf("Error creating device path for disk %d\n", args.disk_number);
        return;
    }

    if (argc == 3) {

        switch(tolower(argv[2][0])) {
            case 'r':
                shareMode = FILE_SHARE_READ;
                break;

            case 'w':
                shareMode = FILE_SHARE_WRITE;
                break;

            case 'c':
                shareMode = FILE_SHARE_READ;
                sectorSize = 2048;
                break;

            default:
                printf("%s is an invalid mode.\n", argv[2]);
                puts("\tr = read");
                puts("\tw = write");
                puts("\tc = read CD (2048 byte sector mode)");
                return;
        }
    }

    fileHandle = CreateFile(string,
       accessMode,
       shareMode,
       NULL,
       OPEN_EXISTING,
       0,
       NULL);

    if (fileHandle == INVALID_HANDLE_VALUE) {
        errorCode = GetLastError();
        printf("Error opening %s. Error: %d\n",
               string, errorCode);
        PrintError(errorCode);
        return;
    }

    DISK_GEOMETRY diskGeometry;
    DWORD bytesReturned;

    if (!DeviceIoControl(fileHandle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        NULL,
        0,
        &diskGeometry,
        sizeof(diskGeometry),
        &bytesReturned,
        NULL)) {
        printf("Error getting disk geometry. Error: %d\n", GetLastError());
        CloseHandle(fileHandle);
        return;
    }


    //
    // Get the alignment requirements
    //

    status = QueryPropertyForDevice(fileHandle, &alignmentMask, &srbType);
    if (!status ) {
        errorCode = GetLastError();
        printf("Error getting device and/or adapter properties; "
               "error was %d\n", errorCode);
        PrintError(errorCode);
        CloseHandle(fileHandle);
        return;
    }

    printf("\n"
           "            *****     Detected Alignment Mask    *****\n"
           "            *****             was %08x       *****\n\n\n",
           alignmentMask);

    //
    // Send SCSI Pass Through
    //
    
    //////////////// read and write ///////////////////////////////////////////////////////////
    if (args.is_read) {
        PerformRead(fileHandle, &args, alignmentMask);
    }
    else if (args.is_write) {
        PerformWrite(fileHandle, &args, alignmentMask);
    }

    puts("            ***** MODE SENSE -- return all pages *****");
    puts("            *****      with SenseInfo buffer     *****\n");

    if(srbType == 1)
    {
        ZeroMemory(&sptwb_ex,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
        sptwb_ex.spt.Version = 0;
        sptwb_ex.spt.Length = sizeof(SCSI_PASS_THROUGH_EX);
        sptwb_ex.spt.ScsiStatus = 0;
        sptwb_ex.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb_ex.spt.StorAddressLength = sizeof(STOR_ADDR_BTL8);
        sptwb_ex.spt.SenseInfoLength = SPT_SENSE_LENGTH;
        sptwb_ex.spt.DataOutTransferLength = 0;
        sptwb_ex.spt.DataInTransferLength = 192;
        sptwb_ex.spt.DataDirection = SCSI_IOCTL_DATA_IN;
        sptwb_ex.spt.TimeOutValue = 2;
        sptwb_ex.spt.StorAddressOffset =
            offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,StorAddress);
        sptwb_ex.StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
        sptwb_ex.StorAddress.Port = 0;
        sptwb_ex.StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
        sptwb_ex.StorAddress.Path = 0;
        sptwb_ex.StorAddress.Target = 1;
        sptwb_ex.StorAddress.Lun = 0;
        sptwb_ex.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucSenseBuf);
        sptwb_ex.spt.DataOutBufferOffset = 0;
        sptwb_ex.spt.DataInBufferOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf);
        sptwb_ex.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb_ex.spt.Cdb[2] = MODE_SENSE_RETURN_ALL;
        sptwb_ex.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf) +
           sptwb_ex.spt.DataInTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_EX,
                                 &sptwb_ex,
                                 sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
                                 &sptwb_ex,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResultsEx(status,returned,&sptwb_ex,length);
    }
    else
    {
        ZeroMemory(&sptwb,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS));
        sptwb.spt.Length = sizeof(SCSI_PASS_THROUGH);
        sptwb.spt.PathId = 0;
        sptwb.spt.TargetId = 1;
        sptwb.spt.Lun = 0;
        sptwb.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb.spt.SenseInfoLength = SPT_SENSE_LENGTH;
        sptwb.spt.DataIn = SCSI_IOCTL_DATA_IN;
        sptwb.spt.DataTransferLength = 192;
        sptwb.spt.TimeOutValue = 2;
        sptwb.spt.DataBufferOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf);
        sptwb.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucSenseBuf);
        sptwb.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb.spt.Cdb[2] = MODE_SENSE_RETURN_ALL;
        sptwb.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf) +
           sptwb.spt.DataTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH,
                                 &sptwb,
                                 sizeof(SCSI_PASS_THROUGH),
                                 &sptwb,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResults(status,returned,&sptwb,length);
    }


    printf("            ***** MODE SENSE -- return all pages *****\n");
    printf("            *****    without SenseInfo buffer    *****\n\n");

    if(srbType == 1)
    {
        ZeroMemory(&sptwb_ex,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
        sptwb_ex.spt.Version = 0;
        sptwb_ex.spt.Length = sizeof(SCSI_PASS_THROUGH_EX);
        sptwb_ex.spt.ScsiStatus = 0;
        sptwb_ex.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb_ex.spt.StorAddressLength = sizeof(STOR_ADDR_BTL8);
        sptwb_ex.spt.SenseInfoLength = 0;
        sptwb_ex.spt.DataOutTransferLength = 0;
        sptwb_ex.spt.DataInTransferLength = 192;
        sptwb_ex.spt.DataDirection = SCSI_IOCTL_DATA_IN;
        sptwb_ex.spt.TimeOutValue = 2;
        sptwb_ex.spt.StorAddressOffset =
            offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,StorAddress);
        sptwb_ex.StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
        sptwb_ex.StorAddress.Port = 0;
        sptwb_ex.StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
        sptwb_ex.StorAddress.Path = 0;
        sptwb_ex.StorAddress.Target = 1;
        sptwb_ex.StorAddress.Lun = 0;
        sptwb_ex.spt.SenseInfoOffset = 0;
        sptwb_ex.spt.DataOutBufferOffset = 0;
        sptwb_ex.spt.DataInBufferOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf);
        sptwb_ex.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb_ex.spt.Cdb[2] = MODE_SENSE_RETURN_ALL;
        sptwb_ex.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf) +
           sptwb_ex.spt.DataInTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_EX,
                                 &sptwb_ex,
                                 sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
                                 &sptwb_ex,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResultsEx(status,returned,&sptwb_ex,length);
    }
    else
    {
        ZeroMemory(&sptwb,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS));
        sptwb.spt.Length = sizeof(SCSI_PASS_THROUGH);
        sptwb.spt.PathId = 0;
        sptwb.spt.TargetId = 1;
        sptwb.spt.Lun = 0;
        sptwb.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb.spt.SenseInfoLength = 0;
        sptwb.spt.DataIn = SCSI_IOCTL_DATA_IN;
        sptwb.spt.DataTransferLength = 192;
        sptwb.spt.TimeOutValue = 2;
        sptwb.spt.DataBufferOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf);
        sptwb.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb.spt.Cdb[2] = MODE_SENSE_RETURN_ALL;
        sptwb.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf) +
           sptwb.spt.DataTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH,
                                 &sptwb,
                                 sizeof(SCSI_PASS_THROUGH),
                                 &sptwb,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResults(status,returned,&sptwb,length);
    }


    printf("            *****      TEST UNIT READY      *****\n");
    printf("            *****   DataInBufferLength = 0  *****\n\n");

    if(srbType == 1)
    {
        ZeroMemory(&sptwb_ex,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
        sptwb_ex.spt.Version = 0;
        sptwb_ex.spt.Length = sizeof(SCSI_PASS_THROUGH_EX);
        sptwb_ex.spt.ScsiStatus = 0;
        sptwb_ex.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb_ex.spt.StorAddressLength = sizeof(STOR_ADDR_BTL8);
        sptwb_ex.spt.SenseInfoLength = SPT_SENSE_LENGTH;
        sptwb_ex.spt.DataOutTransferLength = 0;
        sptwb_ex.spt.DataInTransferLength = 0;
        sptwb_ex.spt.DataDirection = SCSI_IOCTL_DATA_IN;
        sptwb_ex.spt.TimeOutValue = 2;
        sptwb_ex.spt.StorAddressOffset =
            offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,StorAddress);
        sptwb_ex.StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
        sptwb_ex.StorAddress.Port = 0;
        sptwb_ex.StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
        sptwb_ex.StorAddress.Path = 0;
        sptwb_ex.StorAddress.Target = 1;
        sptwb_ex.StorAddress.Lun = 0;
        sptwb_ex.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucSenseBuf);
        sptwb_ex.spt.DataOutBufferOffset = 0;
        sptwb_ex.spt.DataInBufferOffset = 0;
        sptwb_ex.spt.Cdb[0] = SCSIOP_TEST_UNIT_READY;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_EX,
                                 &sptwb_ex,
                                 sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
                                 &sptwb_ex,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResultsEx(status,returned,&sptwb_ex,length);
    }
    else
    {
        ZeroMemory(&sptwb,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS));
        sptwb.spt.Length = sizeof(SCSI_PASS_THROUGH);
        sptwb.spt.PathId = 0;
        sptwb.spt.TargetId = 1;
        sptwb.spt.Lun = 0;
        sptwb.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb.spt.SenseInfoLength = SPT_SENSE_LENGTH;
        sptwb.spt.DataIn = SCSI_IOCTL_DATA_IN;
        sptwb.spt.DataTransferLength = 0;
        sptwb.spt.TimeOutValue = 2;
        sptwb.spt.DataBufferOffset = 0;
        sptwb.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucSenseBuf);
        sptwb.spt.Cdb[0] = SCSIOP_TEST_UNIT_READY;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH,
                                 &sptwb,
                                 sizeof(SCSI_PASS_THROUGH),
                                 &sptwb,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResults(status,returned,&sptwb,length);
    }


    //
    //  Do a mode sense with a bad data buffer offset.  This will fail.
    //
    printf("            *****      MODE SENSE -- return all pages      *****\n");
    printf("            *****   bad DataBufferOffset -- should fail    *****\n\n");

    if(srbType == 1)
    {
        ZeroMemory(&sptwb_ex,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
        sptwb_ex.spt.Version = 0;
        sptwb_ex.spt.Length = sizeof(SCSI_PASS_THROUGH_EX);
        sptwb_ex.spt.ScsiStatus = 0;
        sptwb_ex.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb_ex.spt.StorAddressLength = sizeof(STOR_ADDR_BTL8);
        sptwb_ex.spt.SenseInfoLength = SPT_SENSE_LENGTH;
        sptwb_ex.spt.DataOutTransferLength = 0;
        sptwb_ex.spt.DataInTransferLength = 192;
        sptwb_ex.spt.DataDirection = SCSI_IOCTL_DATA_IN;
        sptwb_ex.spt.TimeOutValue = 2;
        sptwb_ex.spt.StorAddressOffset =
            offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,StorAddress);
        sptwb_ex.StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
        sptwb_ex.StorAddress.Port = 0;
        sptwb_ex.StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
        sptwb_ex.StorAddress.Path = 0;
        sptwb_ex.StorAddress.Target = 1;
        sptwb_ex.StorAddress.Lun = 0;
        sptwb_ex.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucSenseBuf);
        sptwb_ex.spt.DataOutBufferOffset = 0;
        sptwb_ex.spt.DataInBufferOffset = 0;
        sptwb_ex.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb_ex.spt.Cdb[2] = MODE_SENSE_RETURN_ALL;
        sptwb_ex.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf) +
           sptwb_ex.spt.DataInTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_EX,
                                 &sptwb_ex,
                                 sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
                                 &sptwb_ex,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResultsEx(status,returned,&sptwb_ex,length);
    }
    else
    {
        ZeroMemory(&sptwb,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS));
        sptwb.spt.Length = sizeof(SCSI_PASS_THROUGH);
        sptwb.spt.PathId = 0;
        sptwb.spt.TargetId = 1;
        sptwb.spt.Lun = 0;
        sptwb.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb.spt.SenseInfoLength = 0;
        sptwb.spt.DataIn = SCSI_IOCTL_DATA_IN;
        sptwb.spt.DataTransferLength = 192;
        sptwb.spt.TimeOutValue = 2;
        sptwb.spt.DataBufferOffset = 0;
        sptwb.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucSenseBuf);
        sptwb.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb.spt.Cdb[2] = MODE_SENSE_RETURN_ALL;
        sptwb.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf) +
           sptwb.spt.DataTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH,
                                 &sptwb,
                                 sizeof(SCSI_PASS_THROUGH),
                                 &sptwb,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResults(status,returned,&sptwb,length);
    }


    //
    // Get caching mode sense page.
    //
    printf("            *****               MODE SENSE                  *****\n");
    printf("            *****     return caching mode sense page        *****\n\n");

    if(srbType == 1)
    {
        ZeroMemory(&sptwb_ex,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
        sptwb_ex.spt.Version = 0;
        sptwb_ex.spt.Length = sizeof(SCSI_PASS_THROUGH_EX);
        sptwb_ex.spt.ScsiStatus = 0;
        sptwb_ex.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb_ex.spt.StorAddressLength = sizeof(STOR_ADDR_BTL8);
        sptwb_ex.spt.SenseInfoLength = SPT_SENSE_LENGTH;
        sptwb_ex.spt.DataOutTransferLength = 0;
        sptwb_ex.spt.DataInTransferLength = 192;
        sptwb_ex.spt.DataDirection = SCSI_IOCTL_DATA_IN;
        sptwb_ex.spt.TimeOutValue = 2;
        sptwb_ex.spt.StorAddressOffset =
            offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,StorAddress);
        sptwb_ex.StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
        sptwb_ex.StorAddress.Port = 0;
        sptwb_ex.StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
        sptwb_ex.StorAddress.Path = 0;
        sptwb_ex.StorAddress.Target = 1;
        sptwb_ex.StorAddress.Lun = 0;
        sptwb_ex.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucSenseBuf);
        sptwb_ex.spt.DataOutBufferOffset = 0;
        sptwb_ex.spt.DataInBufferOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf);
        sptwb_ex.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb_ex.spt.Cdb[1] = 0x08; // target shall not return any block descriptors
        sptwb_ex.spt.Cdb[2] = MODE_PAGE_CACHING;
        sptwb_ex.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX,ucDataBuf) +
           sptwb_ex.spt.DataInTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_EX,
                                 &sptwb_ex,
                                 sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
                                 &sptwb_ex,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResultsEx(status,returned,&sptwb_ex,length);
    }
    else
    {
        ZeroMemory(&sptwb,sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS));
        sptwb.spt.Length = sizeof(SCSI_PASS_THROUGH);
        sptwb.spt.PathId = 0;
        sptwb.spt.TargetId = 1;
        sptwb.spt.Lun = 0;
        sptwb.spt.CdbLength = CDB6GENERIC_LENGTH;
        sptwb.spt.SenseInfoLength = SPT_SENSE_LENGTH;
        sptwb.spt.DataIn = SCSI_IOCTL_DATA_IN;
        sptwb.spt.DataTransferLength = 192;
        sptwb.spt.TimeOutValue = 2;
        sptwb.spt.DataBufferOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf);
        sptwb.spt.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucSenseBuf);
        sptwb.spt.Cdb[0] = SCSIOP_MODE_SENSE;
        sptwb.spt.Cdb[1] = 0x08; // target shall not return any block descriptors
        sptwb.spt.Cdb[2] = MODE_PAGE_CACHING;
        sptwb.spt.Cdb[4] = 192;
        length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS,ucDataBuf) +
           sptwb.spt.DataTransferLength;

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH,
                                 &sptwb,
                                 sizeof(SCSI_PASS_THROUGH),
                                 &sptwb,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResults(status,returned,&sptwb,length);
    }


    printf("            *****       WRITE DATA BUFFER operation         *****\n");
    
    dataBuffer = AllocateAlignedBuffer(sectorSize,alignmentMask, &pUnAlignedBuffer);
    FillMemory(dataBuffer,sectorSize/2,'N');
    FillMemory(dataBuffer + sectorSize/2,sectorSize/2,'T');

    if(srbType == 1)
    {
        ZeroMemory(&sptdwb_ex,sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX));
        sptdwb_ex.sptd.Version = 0;
        sptdwb_ex.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT_EX);
        sptdwb_ex.sptd.ScsiStatus = 0;
        sptdwb_ex.sptd.CdbLength = CDB10GENERIC_LENGTH;
        sptdwb_ex.sptd.StorAddressLength = sizeof(STOR_ADDR_BTL8);
        sptdwb_ex.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
        sptdwb_ex.sptd.DataOutTransferLength = sectorSize;
        sptdwb_ex.sptd.DataInTransferLength = 0;
        sptdwb_ex.sptd.DataDirection = SCSI_IOCTL_DATA_OUT;
        sptdwb_ex.sptd.TimeOutValue = 2;
        sptdwb_ex.sptd.StorAddressOffset =
            offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX,StorAddress);
        sptdwb_ex.StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
        sptdwb_ex.StorAddress.Port = 0;
        sptdwb_ex.StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
        sptdwb_ex.StorAddress.Path = 0;
        sptdwb_ex.StorAddress.Target = 1;
        sptdwb_ex.StorAddress.Lun = 0;
        sptdwb_ex.sptd.SenseInfoOffset = 
           offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX,ucSenseBuf);
        sptdwb_ex.sptd.DataOutBuffer = dataBuffer;
        sptdwb_ex.sptd.DataInBuffer = NULL;
        sptdwb_ex.sptd.Cdb[0] = SCSIOP_WRITE_DATA_BUFF;
        sptdwb_ex.sptd.Cdb[1] = 2;                         // Data mode
        sptdwb_ex.sptd.Cdb[7] = (UCHAR)(sectorSize >> 8);  // Parameter List length
        sptdwb_ex.sptd.Cdb[8] = 0;
        length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_DIRECT_EX,
                                 &sptdwb_ex,
                                 length,
                                 &sptdwb_ex,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResultsEx(status,returned,
           (PSCSI_PASS_THROUGH_WITH_BUFFERS_EX)&sptdwb_ex,length);

        if ((sptdwb_ex.sptd.ScsiStatus == 0) && (status != 0)) {
           PrintDataBuffer(dataBuffer,sptdwb_ex.sptd.DataOutTransferLength);
        }
    }
    else
    {
        ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
        sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sptdwb.sptd.PathId = 0;
        sptdwb.sptd.TargetId = 1;
        sptdwb.sptd.Lun = 0;
        sptdwb.sptd.CdbLength = CDB10GENERIC_LENGTH;
        sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
        sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_OUT;
        sptdwb.sptd.DataTransferLength = sectorSize;
        sptdwb.sptd.TimeOutValue = 2;
        sptdwb.sptd.DataBuffer = dataBuffer;
        sptdwb.sptd.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER,ucSenseBuf);
        sptdwb.sptd.Cdb[0] = SCSIOP_WRITE_DATA_BUFF;
        sptdwb.sptd.Cdb[1] = 2;                         // Data mode
        sptdwb.sptd.Cdb[7] = (UCHAR)(sectorSize >> 8);  // Parameter List length
        sptdwb.sptd.Cdb[8] = 0;
        length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                 &sptdwb,
                                 length,
                                 &sptdwb,
                                 length,
                                 &returned,
                                 FALSE);
        
        PrintStatusResults(status,returned,
           (PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb,length);

        if ((sptdwb.sptd.ScsiStatus == 0) && (status != 0)) {
           PrintDataBuffer(dataBuffer,sptdwb.sptd.DataTransferLength);
        }
    }


    printf("            *****       READ DATA BUFFER operation         *****\n");

    ZeroMemory(dataBuffer,sectorSize);

    if(srbType == 1)
    {
        ZeroMemory(&sptdwb_ex,sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX));
        sptdwb_ex.sptd.Version = 0;
        sptdwb_ex.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT_EX);
        sptdwb_ex.sptd.ScsiStatus = 0;
        sptdwb_ex.sptd.CdbLength = CDB10GENERIC_LENGTH;
        sptdwb_ex.sptd.StorAddressLength = sizeof(STOR_ADDR_BTL8);
        sptdwb_ex.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
        sptdwb_ex.sptd.DataOutTransferLength = 0;
        sptdwb_ex.sptd.DataInTransferLength = sectorSize;
        sptdwb_ex.sptd.DataDirection = SCSI_IOCTL_DATA_IN;
        sptdwb_ex.sptd.TimeOutValue = 2;
        sptdwb_ex.sptd.StorAddressOffset =
            offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX,StorAddress);
        sptdwb_ex.StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
        sptdwb_ex.StorAddress.Port = 0;
        sptdwb_ex.StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
        sptdwb_ex.StorAddress.Path = 0;
        sptdwb_ex.StorAddress.Target = 1;
        sptdwb_ex.StorAddress.Lun = 0;
        sptdwb_ex.sptd.SenseInfoOffset = 
           offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX,ucSenseBuf);
        sptdwb_ex.sptd.DataOutBuffer = NULL;
        sptdwb_ex.sptd.DataInBuffer = dataBuffer;
        sptdwb_ex.sptd.Cdb[0] = SCSIOP_READ_DATA_BUFF;
        sptdwb_ex.sptd.Cdb[1] = 2;                         // Data mode
        sptdwb_ex.sptd.Cdb[7] = (UCHAR)(sectorSize >> 8);  // Parameter List length
        sptdwb_ex.sptd.Cdb[8] = 0;
        length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_DIRECT_EX,
                                 &sptdwb_ex,
                                 length,
                                 &sptdwb_ex,
                                 length,
                                 &returned,
                                 FALSE);

        PrintStatusResultsEx(status,returned,
           (PSCSI_PASS_THROUGH_WITH_BUFFERS_EX)&sptdwb_ex,length);

        if ((sptdwb_ex.sptd.ScsiStatus == 0) && (status != 0)) {
           PrintDataBuffer(dataBuffer,sptdwb_ex.sptd.DataInTransferLength);
        }
    }
    else
    {
        ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
        sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sptdwb.sptd.PathId = 0;
        sptdwb.sptd.TargetId = 1;
        sptdwb.sptd.Lun = 0;
        sptdwb.sptd.CdbLength = CDB10GENERIC_LENGTH;
        sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_IN;
        sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
        sptdwb.sptd.DataTransferLength = sectorSize;
        sptdwb.sptd.TimeOutValue = 2;
        sptdwb.sptd.DataBuffer = dataBuffer;
        sptdwb.sptd.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER,ucSenseBuf);
        sptdwb.sptd.Cdb[0] = SCSIOP_READ_DATA_BUFF;
        sptdwb.sptd.Cdb[1] = 2;                         // Data mode
        sptdwb.sptd.Cdb[7] = (UCHAR)(sectorSize >> 8);  // Parameter List length
        sptdwb.sptd.Cdb[8] = 0;
        length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                 &sptdwb,
                                 length,
                                 &sptdwb,
                                 length,
                                 &returned,
                                 FALSE);
        
        PrintStatusResults(status,returned,
           (PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb,length);

        if ((sptdwb.sptd.ScsiStatus == 0) && (status != 0)) {
           PrintDataBuffer(dataBuffer,sptdwb.sptd.DataTransferLength);
        }
    }


    if (pUnAlignedBuffer != NULL) {
        free(pUnAlignedBuffer);
    }
    CloseHandle(fileHandle);
}

VOID
PrintError(ULONG ErrorCode)
{
    CHAR errorBuffer[80];
    ULONG count;

    count = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL,
                  ErrorCode,
                  0,
                  errorBuffer,
                  sizeof(errorBuffer),
                  NULL
                  );

    if (count != 0) {
        printf("%s\n", errorBuffer);
    } else {
        printf("Format message failed.  Error: %d\n", GetLastError());
    }
}

VOID
PrintDataBuffer(_In_reads_(BufferLength) PUCHAR DataBuffer, _In_ ULONG BufferLength)
{
    ULONG Cnt;

    printf("      00  01  02  03  04  05  06  07   08  09  0A  0B  0C  0D  0E  0F\n");
    printf("      ---------------------------------------------------------------\n");
    for (Cnt = 0; Cnt < BufferLength; Cnt++) {
       if ((Cnt) % 16 == 0) {
          printf(" %03X  ",Cnt);
          }
       printf("%02X  ", DataBuffer[Cnt]);
       if ((Cnt+1) % 8 == 0) {
          printf(" ");
          }
       if ((Cnt+1) % 16 == 0) {
          printf("\n");
          }
       }
    printf("\n\n");
}

VOID
PrintAdapterDescriptor(PSTORAGE_ADAPTER_DESCRIPTOR AdapterDescriptor)
{
    ULONG trueMaximumTransferLength;
    LPCSTR busType;

    if (AdapterDescriptor->BusType < NUMBER_OF_BUS_TYPE_STRINGS) {
        busType = BusTypeStrings[AdapterDescriptor->BusType];
    } else {
        busType = BusTypeStrings[NUMBER_OF_BUS_TYPE_STRINGS-1];
    }

    // subtract one page, as transfers do not always start on a page boundary
    if (AdapterDescriptor->MaximumPhysicalPages > 1) {
        trueMaximumTransferLength = AdapterDescriptor->MaximumPhysicalPages - 1;
    } else {
        trueMaximumTransferLength = 1;
    }
    // make it into a byte value
    trueMaximumTransferLength <<= PAGE_SHIFT;

    // take the minimum of the two
    if (trueMaximumTransferLength > AdapterDescriptor->MaximumTransferLength) {
        trueMaximumTransferLength = AdapterDescriptor->MaximumTransferLength;
    }

    // always allow at least a single page transfer
    if (trueMaximumTransferLength < PAGE_SIZE) {
        trueMaximumTransferLength = PAGE_SIZE;
    }

    puts("\n            ***** STORAGE ADAPTER DESCRIPTOR DATA *****");
    printf("              Version: %08x\n"
           "            TotalSize: %08x\n"
           "MaximumTransferLength: %08x (bytes)\n"
           " MaximumPhysicalPages: %08x\n"
           "  TrueMaximumTransfer: %08x (bytes)\n"
           "        AlignmentMask: %08x\n"
           "       AdapterUsesPio: %s\n"
           "     AdapterScansDown: %s\n"
           "      CommandQueueing: %s\n"
           "  AcceleratedTransfer: %s\n"
           "             Bus Type: %s\n"
           "    Bus Major Version: %04x\n"
           "    Bus Minor Version: %04x\n",
           AdapterDescriptor->Version,
           AdapterDescriptor->Size,
           AdapterDescriptor->MaximumTransferLength,
           AdapterDescriptor->MaximumPhysicalPages,
           trueMaximumTransferLength,
           AdapterDescriptor->AlignmentMask,
           BOOLEAN_TO_STRING(AdapterDescriptor->AdapterUsesPio),
           BOOLEAN_TO_STRING(AdapterDescriptor->AdapterScansDown),
           BOOLEAN_TO_STRING(AdapterDescriptor->CommandQueueing),
           BOOLEAN_TO_STRING(AdapterDescriptor->AcceleratedTransfer),
           busType,
           AdapterDescriptor->BusMajorVersion,
           AdapterDescriptor->BusMinorVersion);




    printf("\n\n");
}

VOID
PrintDeviceDescriptor(PSTORAGE_DEVICE_DESCRIPTOR DeviceDescriptor)
{
    LPCSTR vendorId = "";
    LPCSTR productId = "";
    LPCSTR productRevision = "";
    LPCSTR serialNumber = "";
    LPCSTR busType;

    if ((ULONG)DeviceDescriptor->BusType < NUMBER_OF_BUS_TYPE_STRINGS) {
        busType = BusTypeStrings[DeviceDescriptor->BusType];
    } else {
        busType = BusTypeStrings[NUMBER_OF_BUS_TYPE_STRINGS-1];
    }

    if ((DeviceDescriptor->ProductIdOffset != 0) &&
        (DeviceDescriptor->ProductIdOffset != -1)) {
        productId        = (LPCSTR)(DeviceDescriptor);
        productId       += (ULONG_PTR)DeviceDescriptor->ProductIdOffset;
    }
    if ((DeviceDescriptor->VendorIdOffset != 0) &&
        (DeviceDescriptor->VendorIdOffset != -1)) {
        vendorId         = (LPCSTR)(DeviceDescriptor);
        vendorId        += (ULONG_PTR)DeviceDescriptor->VendorIdOffset;
    }
    if ((DeviceDescriptor->ProductRevisionOffset != 0) &&
        (DeviceDescriptor->ProductRevisionOffset != -1)) {
        productRevision  = (LPCSTR)(DeviceDescriptor);
        productRevision += (ULONG_PTR)DeviceDescriptor->ProductRevisionOffset;
    }
    if ((DeviceDescriptor->SerialNumberOffset != 0) &&
        (DeviceDescriptor->SerialNumberOffset != -1)) {
        serialNumber     = (LPCSTR)(DeviceDescriptor);
        serialNumber    += (ULONG_PTR)DeviceDescriptor->SerialNumberOffset;
    }


    puts("\n            ***** STORAGE DEVICE DESCRIPTOR DATA *****");
    printf("              Version: %08x\n"
           "            TotalSize: %08x\n"
           "           DeviceType: %08x\n"
           "   DeviceTypeModifier: %08x\n"
           "       RemovableMedia: %s\n"
           "      CommandQueueing: %s\n"
           "            Vendor Id: %s\n"
           "           Product Id: %s\n"
           "     Product Revision: %s\n"
           "        Serial Number: %s\n"
           "             Bus Type: %s\n"
           "       Raw Properties: %s\n",
           DeviceDescriptor->Version,
           DeviceDescriptor->Size,
           DeviceDescriptor->DeviceType,
           DeviceDescriptor->DeviceTypeModifier,
           BOOLEAN_TO_STRING(DeviceDescriptor->RemovableMedia),
           BOOLEAN_TO_STRING(DeviceDescriptor->CommandQueueing),
           vendorId,
           productId,
           productRevision,
           serialNumber,
           busType,
           (DeviceDescriptor->RawPropertiesLength ? "Follows" : "None"));
    if (DeviceDescriptor->RawPropertiesLength != 0) {
        PrintDataBuffer(DeviceDescriptor->RawDeviceProperties,
                        DeviceDescriptor->RawPropertiesLength);
    }
    printf("\n\n");
}

_Success_(return != NULL)
_Post_writable_byte_size_(size)
PUCHAR
AllocateAlignedBuffer(
    _In_ ULONG size,
    _In_ ULONG AlignmentMask,
    _Outptr_result_maybenull_ PUCHAR *pUnAlignedBuffer)
{
    PUCHAR ptr;

    // NOTE: This routine does not allow for a way to free
    //       memory.  This is an excercise left for the reader.
    UINT_PTR    align64 = (UINT_PTR)AlignmentMask;

    if (AlignmentMask == 0) {
       ptr = malloc(size);
       *pUnAlignedBuffer = ptr;
    } else {
       ULONG totalSize;

       (void) ULongAdd(size, AlignmentMask, &totalSize);
       ptr = malloc(totalSize);
       *pUnAlignedBuffer = ptr;
       ptr = (PUCHAR)(((UINT_PTR)ptr + align64) & ~align64);
    }

    if (ptr == NULL) {
       printf("Memory allocation error.  Terminating program\n");
       exit(1);
    } else {
       return ptr;
    }
}

VOID
PrintStatusResults(
    BOOL status,DWORD returned,PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb,
    ULONG length)
{
    ULONG errorCode;

    if (!status ) {
       printf( "Error: %d  ",
          errorCode = GetLastError() );
       PrintError(errorCode);
       return;
       }
    if (psptwb->spt.ScsiStatus) {
       PrintSenseInfo(psptwb);
       return;
       }
    else {
       printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
          psptwb->spt.ScsiStatus,returned);
       printf("Data buffer length: %Xh\n\n\n",
          psptwb->spt.DataTransferLength);
       PrintDataBuffer((PUCHAR)psptwb,length);
       }
}

VOID
PrintSenseInfo(PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb)
{
    UCHAR i;

    printf("Scsi status: %02Xh\n\n",psptwb->spt.ScsiStatus);
    if (psptwb->spt.SenseInfoLength == 0) {
       return;
       }
    printf("Sense Info -- consult SCSI spec for details\n");
    printf("-------------------------------------------------------------\n");
    for (i=0; i < psptwb->spt.SenseInfoLength; i++) {
       printf("%02X ",psptwb->ucSenseBuf[i]);
       }
    printf("\n\n");
}

VOID
PrintStatusResultsEx(
    BOOL status,DWORD returned,PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex,
    ULONG length)
{
    ULONG errorCode;

    if (!status ) {
       printf( "Error: %d  ",
          errorCode = GetLastError() );
       PrintError(errorCode);
       return;
       }
    if (psptwb_ex->spt.ScsiStatus) {
       PrintSenseInfoEx(psptwb_ex);
       return;
       }
    else {
       printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
          psptwb_ex->spt.ScsiStatus,returned);
       printf("DataOut buffer length: %Xh\n"
              "DataIn buffer length: %Xh\n\n\n",
          psptwb_ex->spt.DataOutTransferLength,
          psptwb_ex->spt.DataInTransferLength);
       PrintDataBuffer((PUCHAR)psptwb_ex,length);
       }
}

VOID
PrintSenseInfoEx(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex)
{
    ULONG i;

    printf("Scsi status: %02Xh\n\n",psptwb_ex->spt.ScsiStatus);
    if (psptwb_ex->spt.SenseInfoLength == 0) {
       return;
       }
    printf("Sense Info -- consult SCSI spec for details\n");
    printf("-------------------------------------------------------------\n");
    for (i=0; i < psptwb_ex->spt.SenseInfoLength; i++) {
       printf("%02X ",psptwb_ex->ucSenseBuf[i]);
       }
    printf("\n\n");
}

_Success_(return)
BOOL
QueryPropertyForDevice(
    _In_ IN HANDLE DeviceHandle,
    _Out_ OUT PULONG AlignmentMask,
    _Out_ OUT PUCHAR SrbType
    )
{
    PSTORAGE_ADAPTER_DESCRIPTOR adapterDescriptor = NULL;
    PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor = NULL;
    STORAGE_DESCRIPTOR_HEADER header = {0};

    BOOL ok = TRUE;
    BOOL failed = TRUE;
    ULONG i;

    *AlignmentMask = 0; // default to no alignment
    *SrbType = 0; // default to SCSI_REQUEST_BLOCK

    // Loop twice:
    //  First, get size required for storage adapter descriptor
    //  Second, allocate and retrieve storage adapter descriptor
    //  Third, get size required for storage device descriptor
    //  Fourth, allocate and retrieve storage device descriptor
    for (i=0;i<4;i++) {

        PVOID buffer = NULL;
        ULONG bufferSize = 0;
        ULONG returnedData;

        STORAGE_PROPERTY_QUERY query = {0};

        switch(i) {
            case 0: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageAdapterProperty;
                bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
                buffer = &header;
                break;
            }
            case 1: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageAdapterProperty;
                bufferSize = header.Size;
                if (bufferSize != 0) {
                    adapterDescriptor = LocalAlloc(LPTR, bufferSize);
                    if (adapterDescriptor == NULL) {
                        goto Cleanup;
                    }
                }
                buffer = adapterDescriptor;
                break;
            }
            case 2: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageDeviceProperty;
                bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
                buffer = &header;
                break;
            }
            case 3: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageDeviceProperty;
                bufferSize = header.Size;

                if (bufferSize != 0) {
                    deviceDescriptor = LocalAlloc(LPTR, bufferSize);
                    if (deviceDescriptor == NULL) {
                        goto Cleanup;
                    }
                }
                buffer = deviceDescriptor;
                break;
            }
        }

        // buffer can be NULL if the property queried DNE.
        if (buffer != NULL) {
            RtlZeroMemory(buffer, bufferSize);

            // all setup, do the ioctl
            ok = DeviceIoControl(DeviceHandle,
                                 IOCTL_STORAGE_QUERY_PROPERTY,
                                 &query,
                                 sizeof(STORAGE_PROPERTY_QUERY),
                                 buffer,
                                 bufferSize,
                                 &returnedData,
                                 FALSE);
            if (!ok) {
                if (GetLastError() == ERROR_MORE_DATA) {
                    // this is ok, we'll ignore it here
                } else if (GetLastError() == ERROR_INVALID_FUNCTION) {
                    // this is also ok, the property DNE
                } else if (GetLastError() == ERROR_NOT_SUPPORTED) {
                    // this is also ok, the property DNE
                } else {
                    // some unexpected error -- exit out
                    goto Cleanup;
                }
                // zero it out, just in case it was partially filled in.
                RtlZeroMemory(buffer, bufferSize);
            }
        }
    } // end i loop

    // adapterDescriptor is now allocated and full of data.
    // deviceDescriptor is now allocated and full of data.

    if (adapterDescriptor == NULL) {
        printf("   ***** No adapter descriptor supported on the device *****\n");
    } else {
        PrintAdapterDescriptor(adapterDescriptor);
        *AlignmentMask = adapterDescriptor->AlignmentMask;
        *SrbType = adapterDescriptor->SrbType;
    }

    if (deviceDescriptor == NULL) {
        printf("   ***** No device descriptor supported on the device  *****\n");
    } else {
        PrintDeviceDescriptor(deviceDescriptor);
    }

    failed = FALSE;

Cleanup:
    if (adapterDescriptor != NULL) {
        LocalFree( adapterDescriptor );
    }
    if (deviceDescriptor != NULL) {
        LocalFree( deviceDescriptor );
    }
    return (!failed);

}

