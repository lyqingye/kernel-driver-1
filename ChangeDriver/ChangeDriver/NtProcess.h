#include <NtAnalysis.h>

#pragma once



//
//常量声明
//

//HandleTable
#define LEVEL_CODE_MASK 3 

#define LEVEL1_COUNT 512
#define LEVEL2_COUNT 1024
#define LEVEL3_COUNT 1024

#define LEVEL1_MAX 0x800
#define LEVEL2_MAX 0x200000

//
//结构体声明
//



//
//EPROCESS
//







//
//函数声明
//


//
//枚举句柄表
//

//ULONG NpEnumeraHandleTable(PVOID pHandleTable);


//
//进程名取EPROCESS,for XP
//
PEPROCESS NpLookupPorcessByName(CHAR* ProcessName);