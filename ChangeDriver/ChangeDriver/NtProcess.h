#include <NtAnalysis.h>

#pragma once



//
//��������
//

//HandleTable
#define LEVEL_CODE_MASK 3 

#define LEVEL1_COUNT 512
#define LEVEL2_COUNT 1024
#define LEVEL3_COUNT 1024

#define LEVEL1_MAX 0x800
#define LEVEL2_MAX 0x200000

//
//�ṹ������
//



//
//EPROCESS
//







//
//��������
//


//
//ö�پ����
//

//ULONG NpEnumeraHandleTable(PVOID pHandleTable);


//
//������ȡEPROCESS,for XP
//
PEPROCESS NpLookupPorcessByName(CHAR* ProcessName);