#include <Ntifs.h>
#include <ResultStatus.h>

#pragma once 



typedef struct DELAYCLOCK_
{
	KDPC Dpc; //DPC延迟调用
	KTIMER Timer; //时钟对象
	PVOID PrivateContext; //用户私有上下文，用来传递回调过程的参数
	PKDEFERRED_ROUTINE pCallBackProc; //回调过程

}DELAYCLOCK, *PDELAYCLOCK;


//
//初始化定时器
//

BOOLEAN DelayTimerInit(PDELAYCLOCK pTimer, PKDEFERRED_ROUTINE pCallBackProc);

//
//开启定时器
//

BOOLEAN DelaySetTimer(PDELAYCLOCK pTimer, LONGLONG Msce, PVOID UserContext);

//
//关闭定时器
//

BOOLEAN DelayDestroyTimer(PDELAYCLOCK pTimer);