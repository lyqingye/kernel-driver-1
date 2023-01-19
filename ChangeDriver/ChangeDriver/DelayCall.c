#include <DelayCall.h>




//
//��ʼ����ʱ��
//

BOOLEAN DelayTimerInit(PDELAYCLOCK pTimer, PKDEFERRED_ROUTINE pCallBackProc)
{
	//
	//�������
	//
	if (!MmIsAddressValid(pTimer))
	{
		RstatusPrint(DC_STATUS_INVALID_PARAMETE);
		return FALSE;
	}
	if (!MmIsAddressValid(pCallBackProc))
	{
		RstatusPrint(DC_STATUS_INVALID_PARAMETE);
		return FALSE;
	}


	//��ʼ��DPC
	KeInitializeDpc(&pTimer->Dpc, pCallBackProc, pTimer);

	//�󶨻ص�����
	pTimer->pCallBackProc = pCallBackProc;

	//��ʼ����ʱ��
	KeInitializeTimer(&pTimer->Timer);

	//����
	return TRUE;
}


//
//������ʱ��
//

BOOLEAN DelaySetTimer(PDELAYCLOCK pTimer, LONGLONG Msce, PVOID UserContext)
{

	//
	//�������
	//
	if (!MmIsAddressValid(pTimer))
	{
		RstatusPrint(DC_STATUS_INVALID_PARAMETE);
		return FALSE;
	}
	if (Msce == 0)
	{
		RstatusPrint(DC_STATUS_INVALID_PARAMETE);
		return FALSE;
	}


	//����ʱ������
	LARGE_INTEGER due;

	//ʱ������
	due.QuadPart = Msce; // - 10000000 = 1s

	//�����û�˽��������
	pTimer->PrivateContext = UserContext;

	//������ʱ��
	return KeSetTimer(&pTimer->Timer, due, &pTimer->Dpc);
}

//
//�رն�ʱ��
//

BOOLEAN DelayDestroyTimer(PDELAYCLOCK pTimer)
{
	//
	//�������
	//
	if (!MmIsAddressValid(pTimer))
	{
		RstatusPrint(DC_STATUS_INVALID_PARAMETE);
		return FALSE;
	}

	//�رն�ʱ��
	return KeCancelTimer(&pTimer->Timer);
}