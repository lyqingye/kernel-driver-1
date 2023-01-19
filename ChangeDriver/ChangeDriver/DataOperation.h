#include <Ntifs.h>
#include <DelayCall.h>

#pragma once 

//�Զ������Ͷ���
typedef  USHORT  WORD16;
typedef  CHAR BYTE8;

//------------------------------------------------------------------------------------------------------------------------------------------

//�ַ�����

typedef struct _ANSI_STRING_LIST_ENTRY{      

	 struct _ANSI_STRING_LIST_ENTRY *pNext_Entry;
	 ANSI_STRING  Datainfo;

}ANSI_STRING_LIST_ENTRY,*PANSI_STRING_LIST_ENTRY;

typedef struct _ANSI_STRING_LIST_HEADER{    

	ULONG NumberOfMerber;
	struct _ANSI_STRING_LIST_ENTRY *pNextEntry;

}ANSI_STRING_LIST_HEADER,*PANSI_STRING_LIST_HEADER;

//
//��ʼ������ͷ
//
PANSI_STRING_LIST_HEADER InitializaAnsiList();

//
//�����Ա
//
PANSI_STRING_LIST_ENTRY IncreaseAnsiList(PANSI_STRING_LIST_HEADER pListHead, PANSI_STRING pData);

//
//�ͷ�����ͷ����Ա��������
//
PANSI_STRING_LIST_ENTRY ReleaseAnsiList(PANSI_STRING_LIST_HEADER  ListHead);

//------------------------------------------------------------------------------------------------------------------------------------------


//------------------------------------------------------------------------------------------------------------------------------------------


//Ssdt HOOK ��������

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
	struct _SSDT_HOOK_LIST_ENTRY *latelyListEntry; //��¼�������ӽ����µ�list,�Ա�����³�Ա

}SSDT_HOOK_LIST_HEADER, *PSSDT_HOOK_LIST_HEADER;


//
//��ʼ������ͷ
//
PSSDT_HOOK_LIST_HEADER InitializaHookList();

//
//�����Ա
//
PSSDT_HOOK_LIST_ENTRY  IncreaseHookList(PSSDT_HOOK_LIST_HEADER pListHeader, PSSDT_HOOK_LIST_ENTRY pData);

//
//�ͷ�����
//
PSSDT_HOOK_LIST_ENTRY  ReleaseHookList(PSSDT_HOOK_LIST_HEADER  pListHeader);

//------------------------------------------------------------------------------------------------------------------------------------------


//
//��Ansi����ת��ΪMap
//

PVOID AnsiListToMapping(PANSI_STRING_LIST_HEADER ListHead, BOOLEAN Release, PULONG MapSize);


//
//��Mapת��ΪAnsi����
//

PANSI_STRING_LIST_HEADER MappingToAnsiList(PVOID Map,ULONG Number, BOOLEAN Release);

//
//�����ڴ���Ansi�ַ�������
//

ULONG DPeAnsiStrlen(PVOID pStr);