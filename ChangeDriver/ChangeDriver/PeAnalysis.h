#include <Ntifs.h>
#include <ResultStatus.h>
#include <DataOperation.h>

#pragma once 




//
//�Զ�����������
//


typedef  USHORT  WORD16;
typedef  CHAR BYTE8;





//
//��������
//



//ϵͳ����

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE  2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY  4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE  7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS   9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  11
#define IMAGE_DIRECTORY_ENTRY_IAT   12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14





//
//�ṹ������
//


//ϵͳ�ṹ
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD16   e_magic;                     // Magic number
	WORD16   e_cblp;                      // Bytes on last page of file
	WORD16   e_cp;                        // Pages in file
	WORD16   e_crlc;                      // Relocations
	WORD16   e_cparhdr;                   // Size of header in paragraphs
	WORD16   e_minalloc;                  // Minimum extra paragraphs needed
	WORD16   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD16   e_ss;                        // Initial (relative) SS value
	WORD16   e_sp;                        // Initial SP value
	WORD16   e_csum;                      // Checksum
	WORD16   e_ip;                        // Initial IP value
	WORD16   e_cs;                        // Initial (relative) CS value
	WORD16   e_lfarlc;                    // File address of relocation table
	WORD16   e_ovno;                      // Overlay number
	WORD16   e_res[4];                    // Reserved words
	WORD16   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD16   e_oeminfo;                   // OEM information; e_oemid specific
	WORD16   e_res2[10];                  // Reserved words
	ULONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD16  Machine;
	WORD16  NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	WORD16  SizeOfOptionalHeader;
	WORD16  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD16                Magic;
	BYTE8                 MajorLinkerVersion;
	BYTE8                 MinorLinkerVersion;
	ULONG               SizeOfCode;
	ULONG               SizeOfInitializedData;
	ULONG               SizeOfUninitializedData;
	ULONG               AddressOfEntryPoint;
	ULONG               BaseOfCode;
	ULONG               BaseOfData;
	ULONG               ImageBase;
	ULONG               SectionAlignment;
	ULONG               FileAlignment;
	WORD16                MajorOperatingSystemVersion;
	WORD16                MinorOperatingSystemVersion;
	WORD16                MajorImageVersion;
	WORD16                MinorImageVersion;
	WORD16                MajorSubsystemVersion;
	WORD16                MinorSubsystemVersion;
	ULONG               Win32VersionValue;
	ULONG               SizeOfImage;
	ULONG               SizeOfHeaders;
	ULONG               CheckSum;
	WORD16                Subsystem;
	WORD16                DllCharacteristics;
	ULONG               SizeOfStackReserve;
	ULONG               SizeOfStackCommit;
	ULONG               SizeOfHeapReserve;
	ULONG               SizeOfHeapCommit;
	ULONG               LoaderFlags;
	ULONG               NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADER
{
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADER, *PIMAGE_NT_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE8  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	WORD16  NumberOfRelocations;
	WORD16  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG   Characteristics;
	ULONG   TimeDateStamp;
	WORD16    MajorVersion;
	WORD16    MinorVersion;
	ULONG   Name;
	ULONG   Base;
	ULONG   NumberOfFunctions;
	ULONG   NumberOfNames;
	ULONG   AddressOfFunctions;     // RVA from base of image
	ULONG   AddressOfNames;         // RVA from base of image
	ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		ULONG   Characteristics;            // 0 for terminating null import descriptor
		ULONG   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	ULONG   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	ULONG   ForwarderChain;                 // -1 if no forwarders
	ULONG   Name;
	ULONG   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA32 {
	union {
		ULONG ForwarderString;      // PBYTE 
		ULONG Function;             // PDWORD
		ULONG Ordinal;
		ULONG AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA32,*PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD16    Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_BASE_RELOCATION {
	ULONG   VirtualAddress;
	ULONG   SizeOfBlock;
} IMAGE_BASE_RELOCATION,*PIMAGE_BASE_RELOCATION;



//���˽ṹ

typedef struct _EXPORT_DIRECTORY{  //�����������ݽṹ
	PANSI_STRING_LIST_HEADER pfncNamelist; //����һ������������������ͷ
	PVOID pfncRvaTable;	 //����һ�����������ַ��	
	PVOID OrdlnalsTable; //����һ��������ű�
}EXPORT_DIRECTORY, *PEXPORT_DIRECTORY;


typedef struct _IMPORT_DIRECTORY{  //����������ݽṹ
	ULONG dllNumber;		//Dll����
	PVOID pArrPfncNameList; //����һ������,���������������ͷ��ַ��ÿһ������ͷ���浼�뺯������
	PVOID pOrdinalsOrHit;	//����һ����,������HIT�������
	PVOID pArrIatThunkTable; //����һ�����飬������ָ�룬ÿһ��ָ��ָ��һ��IAT��
	PVOID pArrIatFirstThunk; //����һ������,�������ÿһ��DLL��firstThunk
}IMPORT_DIRECTORY, *PIMPORT_DIRECTORY;


typedef struct _EXPORT_SEARCH_VALUE{ //�����������ʱ�򷵻ص�����
	ULONG VirtualAddress;	//���������ַ		
	ULONG FileOffset;		//�����ļ�ƫ��

}EXPORT_SEARCH_VALUE, *PEXPORT_SEARCH_VALUE;


typedef struct _IMPORT_SEARCH_VALUE
{
	ULONG VirulAddress;
	ULONG FileOffset;

}IMPORT_SEARCH_VALUE,*PIMPORT_SEARCH_VALUE;





//
//��������
//


//
//��ȡDOSͷ
//
PIMAGE_DOS_HEADER PeGetDosHeader(IN PVOID FileBuffer);

				  
//
//��ȡNTͷ
//
PIMAGE_NT_HEADER  PeGetNtHeader(IN PVOID FileBuffer);

//
//��ȡ����ͷ
//
PIMAGE_SECTION_HEADER PeGetSectionHeader(IN PVOID FileBuffer);

//
//ö�ٵ�����
//
ULONG PeGetExportTable(IN PVOID FileBuffer, OUT PEXPORT_DIRECTORY pExportDirectory);

//
//ö�ٵ����
//
ULONG PeGetImportTable(IN PVOID FileBuffer, OUT PIMPORT_DIRECTORY pImportDirectory);

//
//ö���ض�λ��
//
ULONG PeGetRelocaTable(PVOID FileBuffer, OUT PVOID pRvaTable);

//
//�ͷŻ�ȡ��Pe������
//
ULONG PeReleaseExportTable(IN PEXPORT_DIRECTORY pExportDirectory);

//
//����������
//
ULONG PeSearchExportTable(IN PVOID FileBuffer, IN PANSI_STRING SearchName, OUT PEXPORT_SEARCH_VALUE pExoirtSearchValue);

//
//���������
//
ULONG PeSearchImportTable(IN PVOID FileBuffer, IN PANSI_STRING SearchName, OUT PIMPORT_SEARCH_VALUE pImportSearchValue);

//
//�����ַת�ļ�ƫ��
//
ULONG PeRvaToFileOffset(PVOID FileBuffer, ULONG Rva);

//
//���ָ������ĵ�ַ
//
ULONG PeTakeOutPoint(PVOID Point);

//
//���ݶ���ֵ�����ڴ��С,�ڴ����ݶ���ֵ��NULL��ǽ���
//
ULONG PeGetMemorySize(PVOID Buffer, ULONG Alignment);

//
//�ⶨ�ڴ���Ansi�ַ�������
//
ULONG PeAnsiStrlen(PVOID pStr);
