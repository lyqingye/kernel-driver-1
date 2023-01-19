#include <NtAnalysis.h>

#include <DelayCall.h>

#pragma once 


//
//结构声明
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
//函数声明
//


//
//初始化Hook框架
//
PSSDT_HOOK_LIST_HEADER InitializaHook(PHOOK_VALUE phookValue);

//
//设置Hook
//

ULONG EnableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry);


//恢复Hook
//
ULONG DisableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry, BOOLEAN IsOldProc, BOOLEAN IsClock);


//
//安装Hook框架
//
		
ULONG InstallHookEngine();


//
//卸载Hook框架
//

ULONG UnInstallHookEngine();