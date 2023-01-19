#include <Ntifs.h>

#pragma once



//
//״̬��������
//

//PeAnalysis
#define PE_STATUS_INVALID_PARAMETE	0x1
#define PE_STATUS_RESULT_SUCCESS    0x2
#define PE_STATUS_RESULT_ERROR		0x3
#define PE_STATUS_MALLOCPOOL_ERROR  0x4
#define PE_STATUS_SEARCHEXPORT_ERROR 0X5

//DelayCall
#define DC_STATUS_INVALID_PARAMETE 0x11
#define DC_STATUS_RESULT_SUCCESS   0x12
#define DC_STATUS_RESULT_ERROR     0x13

//NtAnalysis
#define NT_STATUS_INVALID_PARAMETE 0X21
#define NT_STATUS_RESULT_SUCCESS   0x22
#define NT_STATUS_RESULT_ERROR     0x23
#define NT_STATUS_MALLOCPOOL_ERROR 0x24
#define NT_STATUS_OPENFILE_ERROR   0x25
#define NT_STATUS_GETFILESIZE_ERROR 0x26
#define NT_STATUS_READFILE_ERROR   0X27
#define NT_STATUS_GETKERNELBASE_ERROR 0X28


//Hook
#define HK_STATUS_INVALID_PARAMETE 0x32
#define HK_STATUS_RESULT_SUCCESS   0X33
#define HK_STATUS_RESULT_ERROR	   0x34




//
//��������
//

//
//��ӡ������Ϣ
//
ULONG RstatusPrint(ULONG StatusCode);