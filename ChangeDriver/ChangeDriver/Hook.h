#include <NtAnalysis.h>

#include <DelayCall.h>

#pragma once 


//
//�ṹ����
//

typedef struct _HOOK_VALUE {

	IN ULONG ServicesIndex;
	IN ULONG NewProc;
	IN BOOLEAN Clock;
	IN LONGLONG Cycle_ns; 
	IN PKDEFERRED_ROUTINE CallBackProc;
	IN PSSDT_HOOK_LIST_HEADER pListHeader;
	OUT PSSDT_HOOK_LIST_ENTRY  pNewListEntry;

}HOOK_VALUE,*PHOOK_VALUE;



//
//��������
//


//
//��ʼ��Hook���
//
PSSDT_HOOK_LIST_HEADER InitializaHook(PHOOK_VALUE phookValue);

//
//����Hook
//

ULONG EnableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry);


//�ָ�Hook
//
ULONG DisableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry, BOOLEAN IsOldProc, BOOLEAN IsClock);


//
//��װHook���
//
		
ULONG InstallHookEngine();


//
//ж��Hook���
//

ULONG UnInstallHookEngine();