#include <Ntifs.h>
#include <ResultStatus.h>
#include <DataOperation.h>

#pragma once 




//
//自定义数据类型
//


typedef  USHORT  WORD16;
typedef  CHAR BYTE8;





//
//常量定义
//



//系统常量

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
//结构体声明
//


//系统结构
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



//个人结构

typedef struct _EXPORT_DIRECTORY{  //导出表返回数据结构
	PANSI_STRING_LIST_HEADER pfncNamelist; //返回一个导出函数名称链表头
	PVOID pfncRvaTable;	 //返回一个函数虚拟地址表	
	PVOID OrdlnalsTable; //返回一个函数序号表
}EXPORT_DIRECTORY, *PEXPORT_DIRECTORY;


typedef struct _IMPORT_DIRECTORY{  //导入表返回数据结构
	ULONG dllNumber;		//Dll个数
	PVOID pArrPfncNameList; //返回一个数组,数组里面放着链表头地址，每一个链表头储存导入函数名称
	PVOID pOrdinalsOrHit;	//返回一个表,里面存放HIT或者序号
	PVOID pArrIatThunkTable; //返回一个数组，数组存放指针，每一个指针指向一张IAT表
	PVOID pArrIatFirstThunk; //返回一个数组,里面放着每一个DLL的firstThunk
}IMPORT_DIRECTORY, *PIMPORT_DIRECTORY;


typedef struct _EXPORT_SEARCH_VALUE{ //搜索导出表的时候返回的数据
	ULONG VirtualAddress;	//函数虚拟地址		
	ULONG FileOffset;		//函数文件偏移

}EXPORT_SEARCH_VALUE, *PEXPORT_SEARCH_VALUE;


typedef struct _IMPORT_SEARCH_VALUE
{
	ULONG VirulAddress;
	ULONG FileOffset;

}IMPORT_SEARCH_VALUE,*PIMPORT_SEARCH_VALUE;





//
//函数声明
//


//
//获取DOS头
//
PIMAGE_DOS_HEADER PeGetDosHeader(IN PVOID FileBuffer);

				  
//
//获取NT头
//
PIMAGE_NT_HEADER  PeGetNtHeader(IN PVOID FileBuffer);

//
//获取区段头
//
PIMAGE_SECTION_HEADER PeGetSectionHeader(IN PVOID FileBuffer);

//
//枚举导出表
//
ULONG PeGetExportTable(IN PVOID FileBuffer, OUT PEXPORT_DIRECTORY pExportDirectory);

//
//枚举导入表
//
ULONG PeGetImportTable(IN PVOID FileBuffer, OUT PIMPORT_DIRECTORY pImportDirectory);

//
//枚举重定位表
//
ULONG PeGetRelocaTable(PVOID FileBuffer, OUT PVOID pRvaTable);

//
//释放获取的Pe导出表
//
ULONG PeReleaseExportTable(IN PEXPORT_DIRECTORY pExportDirectory);

//
//搜索导出表
//
ULONG PeSearchExportTable(IN PVOID FileBuffer, IN PANSI_STRING SearchName, OUT PEXPORT_SEARCH_VALUE pExoirtSearchValue);

//
//搜索导入表
//
ULONG PeSearchImportTable(IN PVOID FileBuffer, IN PANSI_STRING SearchName, OUT PIMPORT_SEARCH_VALUE pImportSearchValue);

//
//虚拟地址转文件偏移
//
ULONG PeRvaToFileOffset(PVOID FileBuffer, ULONG Rva);

//
//获得指针里面的地址
//
ULONG PeTakeOutPoint(PVOID Point);

//
//根据对齐值计算内存大小,内存块根据对齐值以NULL标记结束
//
ULONG PeGetMemorySize(PVOID Buffer, ULONG Alignment);

//
//测定内存中Ansi字符串长度
//
ULONG PeAnsiStrlen(PVOID pStr);
