#include <Ntifs.h>
#include <DelayCall.h>

#pragma once 

//自定义类型定义
typedef  USHORT  WORD16;
typedef  CHAR BYTE8;

//------------------------------------------------------------------------------------------------------------------------------------------

//字符链表

typedef struct _ANSI_STRING_LIST_ENTRY{      

	 struct _ANSI_STRING_LIST_ENTRY *pNext_Entry;
	 ANSI_STRING  Datainfo;

}ANSI_STRING_LIST_ENTRY,*PANSI_STRING_LIST_ENTRY;

typedef struct _ANSI_STRING_LIST_HEADER{    

	ULONG NumberOfMerber;
	struct _ANSI_STRING_LIST_ENTRY *pNextEntry;

}ANSI_STRING_LIST_HEADER,*PANSI_STRING_LIST_HEADER;

//
//初始化链表头
//
PANSI_STRING_LIST_HEADER InitializaAnsiList();

//
//插入成员
//
PANSI_STRING_LIST_ENTRY IncreaseAnsiList(PANSI_STRING_LIST_HEADER pListHead, PANSI_STRING pData);

//
//释放链表头及成员所有数据
//
PANSI_STRING_LIST_ENTRY ReleaseAnsiList(PANSI_STRING_LIST_HEADER  ListHead);

//------------------------------------------------------------------------------------------------------------------------------------------


//------------------------------------------------------------------------------------------------------------------------------------------


//Ssdt HOOK 所用链表

typedef struct _SSDT_HOOK_LIST_ENTRY {
	struct _SSDT_HOOK_LIST_ENTRY *pNextEntry;
	struct DELAYCLOCK_ delayClock;
	ULONG  hookProcIndex;
	ULONG  OldProc;
	ULONG  NewProc;
	ULONG  pDelayClock;

}SSDT_HOOK_LIST_ENTRY, *PSSDT_HOOK_LIST_ENTRY;

typedef struct _SSDT_HOOK_LIST_HEADER{

	ULONG NumberOfMerber;
	struct _SSDT_HOOK_LIST_ENTRY *pNextEntry;
	struct _SSDT_HOOK_LIST_ENTRY *latelyListEntry; //记录最近才添加进的新的list,以便添加新成员

}SSDT_HOOK_LIST_HEADER, *PSSDT_HOOK_LIST_HEADER;


//
//初始化链表头
//
PSSDT_HOOK_LIST_HEADER InitializaHookList();

//
//插入成员
//
PSSDT_HOOK_LIST_ENTRY  IncreaseHookList(PSSDT_HOOK_LIST_HEADER pListHeader, PSSDT_HOOK_LIST_ENTRY pData);

//
//释放链表
//
PSSDT_HOOK_LIST_ENTRY  ReleaseHookList(PSSDT_HOOK_LIST_HEADER  pListHeader);

//------------------------------------------------------------------------------------------------------------------------------------------


//
//将Ansi链表转换为Map
//

PVOID AnsiListToMapping(PANSI_STRING_LIST_HEADER ListHead, BOOLEAN Release, PULONG MapSize);


//
//将Map转换为Ansi链表
//

PANSI_STRING_LIST_HEADER MappingToAnsiList(PVOID Map,ULONG Number, BOOLEAN Release);

//
//测量内存中Ansi字符串长度
//

ULONG DPeAnsiStrlen(PVOID pStr);