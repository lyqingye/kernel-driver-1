#include <DelayCall.h>




//
//初始化定时器
//

BOOLEAN DelayTimerInit(PDELAYCLOCK pTimer, PKDEFERRED_ROUTINE pCallBackProc)
{
	//
	//参数检查
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


	//初始化DPC
	KeInitializeDpc(&pTimer->Dpc, pCallBackProc, pTimer);

	//绑定回调函数
	pTimer->pCallBackProc = pCallBackProc;

	//初始化定时器
	KeInitializeTimer(&pTimer->Timer);

	//返回
	return TRUE;
}


//
//开启定时器
//

BOOLEAN DelaySetTimer(PDELAYCLOCK pTimer, LONGLONG Msce, PVOID UserContext)
{

	//
	//参数检查
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


	//设置时钟属性
	LARGE_INTEGER due;

	//时钟周期
	due.QuadPart = Msce; // - 10000000 = 1s

	//设置用户私有上下文
	pTimer->PrivateContext = UserContext;

	//开启定时器
	return KeSetTimer(&pTimer->Timer, due, &pTimer->Dpc);
}

//
//关闭定时器
//

BOOLEAN DelayDestroyTimer(PDELAYCLOCK pTimer)
{
	//
	//参数检查
	//
	if (!MmIsAddressValid(pTimer))
	{
		RstatusPrint(DC_STATUS_INVALID_PARAMETE);
		return FALSE;
	}

	//关闭定时器
	return KeCancelTimer(&pTimer->Timer);
}