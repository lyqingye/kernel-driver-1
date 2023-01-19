#include <Ntifs.h>
#include <ResultStatus.h>

#pragma once 



typedef struct DELAYCLOCK_
{
	KDPC Dpc; //DPC�ӳٵ���
	KTIMER Timer; //ʱ�Ӷ���
	PVOID PrivateContext; //�û�˽�������ģ��������ݻص����̵Ĳ���
	PKDEFERRED_ROUTINE pCallBackProc; //�ص�����

}DELAYCLOCK, *PDELAYCLOCK;


//
//��ʼ����ʱ��
//

BOOLEAN DelayTimerInit(PDELAYCLOCK pTimer, PKDEFERRED_ROUTINE pCallBackProc);

//
//������ʱ��
//

BOOLEAN DelaySetTimer(PDELAYCLOCK pTimer, LONGLONG Msce, PVOID UserContext);

//
//�رն�ʱ��
//

BOOLEAN DelayDestroyTimer(PDELAYCLOCK pTimer);