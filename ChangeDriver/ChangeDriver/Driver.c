#include <Ntifs.h>
#include <PeAnalysis.h>
#include <NtAnalysis.h>
#include <NtProcess.h>
#include <Hook.h>
#include <Excalibur.h>

#pragma once 




//全局变量 

SERVICETABLE ServiceTable;
SERVICETABLE_SHADOW ServiceTableShadow;










//
//函数声明
//


//
//驱动卸载
//
VOID DriverUnload(PDRIVER_OBJECT pDriverObject);

//
//驱动入口
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);

//
//派遣函数 Create And Close
//

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//
//派遣函数 IoControl
//


NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

//
//预处理
//


#pragma alloc_text(INT,DriverEntry)
#pragma alloc_text (PAGED,DispatchCreateClose)
#pragma alloc_text (PAGED,DispatchIoControl)


//
//驱动卸载例程
//

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{

	DbgPrint("Entry unload\n");

	UNICODE_STRING SymbolicLinkName;

	//
	//可以卸载其他例程
	//

	NtDeleteServiceTable(&ServiceTable);
	NtDelectServiceTableShadow(&ServiceTableShadow);
	NtRestoreKiFastCallEntry();

	//
	//驱动卸载处理
	//
	RtlInitUnicodeString(&SymbolicLinkName, L"\\??\\Excalibur");

	//删除符号链接
	IoDeleteSymbolicLink(&SymbolicLinkName);

	//删除驱动对象
	IoDeleteDevice(pDriverObject->DeviceObject);



	
}


//
//Irp->DispatchCreateClose
//
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

	//
	//设置Irp状态信息
	//
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	//
	//返回处理Irp
	//
	IoCompleteRequest(Irp, 0);

	//
	//return
	//
	return STATUS_SUCCESS;
}

//
//Irp -> DispatchIoControl
//

NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{

	
	KdPrint(("Enter Control\n"));
	//
	//在这开始处理Irp
	//
	//--------------------------------------------------------------------------------
	
	NTSTATUS Status;
	PIO_STACK_LOCATION Stack = NULL;


	ULONG Code = 0; //控制码
	ULONG NeedLength = 0; // 实际操作长度
	ULONG InBufferLength = 0; //输入缓冲区长度
	ULONG OutBufferLength = 0; //输出缓冲区长度
	
	PVOID InBuffer = NULL;
	PVOID OutBuffer = NULL;
	ULONG Value = 0;
	PVOID Table = NULL;
	PVOID Map = NULL;
	//获取设备栈
	Stack = IoGetCurrentIrpStackLocation(Irp);
	//获取输入缓冲区大小
	InBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
	//获取输出缓冲区大小
	OutBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	//获取控制码
	Code = Stack->Parameters.DeviceIoControl.IoControlCode;

	
	//
	//处理控制请求
	//

	switch (Code) //0x800 ~ 0xFFF
	{
	case CTL_CODE_GET_SERVICETABLE_NUMBER:
		{
				 //获取返回缓冲区
				 OutBuffer = Irp->AssociatedIrp.SystemBuffer;

				 NeedLength = OutBufferLength;

				 if (NeedLength == 0)
				 {
					 Status = STATUS_INVALID_VARIANT;
					 break;
				 }

				 ULONG Number = ExGetServiceTableNumber(&ServiceTable);

				 if (Number == 0)
				 {
					 Status = STATUS_INVALID_VARIANT;
				 }
				 else{
					 Status = STATUS_SUCCESS;
					 //拷贝返回数据
					 if (OutBuffer)
					 {
						 RtlCopyMemory(OutBuffer, &Number, NeedLength);
					 }
									 
				 }

				 break;

		}


	case CTL_CODE_GET_SERVICETABLE_FNC_NAME: //Test
		{				
			
				//获取返回缓冲区
				OutBuffer = Irp->AssociatedIrp.SystemBuffer;

				

				//获取Map
				Map = ExGetServiceTableFncName(&NeedLength, &ServiceTable);

				if (Map == NULL)
				{
					Status = STATUS_INVALID_VARIANT;
					break;
				}
				else{
					Status = STATUS_SUCCESS;

					//拷贝返回数据
					if (OutBuffer)
					{
						RtlCopyMemory(OutBuffer, Map, NeedLength);
					}
				}

				if (MmIsAddressValid(Map))
				{
					ExFreePoolWithTag(Map, 1024);
				}

				break;
		}

	case CTL_CODE_GET_SERVICETABLE_MEM_FNC:
	{
					 // 获取返回缓冲区
					OutBuffer = Irp->AssociatedIrp.SystemBuffer;


					ULONG Number = ExGetServiceTableNumber(&ServiceTable);

					NeedLength = Number*sizeof(PVOID);

					//获取Map
					Map = ExGetServiceTableMemFnc();

					if (Map == NULL)
					{
							Status = STATUS_INVALID_VARIANT;
							break;
					}
					else
					{
						  Status = STATUS_SUCCESS;

						  ///拷贝返回数据
						  if (OutBuffer)
						  {
							  RtlCopyMemory(OutBuffer, Map, NeedLength);;
						  }

					}		
					

					if (MmIsAddressValid(Map))
					{
						ExFreePoolWithTag(Map, 1024);
					}


					break;
	}

	case CTL_CODE_GET_SERVICETABLE_FILE_FNC:
	{
				// 获取返回缓冲区
				OutBuffer = Irp->AssociatedIrp.SystemBuffer;

				ULONG Number = ExGetServiceTableNumber(&ServiceTable);

				NeedLength = Number*sizeof(PVOID);

				//获取Map
				Table = ExGetServiceTableFileFnc();

				if (Table == NULL)
				{
					Status = STATUS_INVALID_VARIANT;
					break;
				}
				else
				{
					Status = STATUS_SUCCESS;

					///拷贝返回数据
					if (OutBuffer)
					{
						RtlCopyMemory(OutBuffer, Table, NeedLength);
					}
					

				}

				if (MmIsAddressValid(Table))
				{
					ExFreePoolWithTag(Table, 1024);
				}
				
				break;
	 }

	case CTL_CODE_GET_SERVICETABLE_SHADOW_MEM_FNC:
	{		
				// 获取返回缓冲区
				OutBuffer = Irp->AssociatedIrp.SystemBuffer;

				ULONG Number = 0;

				Number = ExGetServiceTableShadowNumber();

				NeedLength = Number*sizeof(PVOID);

				Table = ExGetServiceTableShadowMemFnc();

				if (Table == NULL)
				{
					Status = STATUS_INVALID_VARIANT;
					break;
				}
				else
				{
					Status = STATUS_SUCCESS;

					///拷贝返回数据
					if (OutBuffer)
					{
						RtlCopyMemory(OutBuffer, Table, NeedLength);
					}

				}

				if (MmIsAddressValid(Table))
				{
					ExFreePoolWithTag(Table, 1024);
				}

				break;

	 }
	case CTL_CODE_GET_SERVICETABLE_SHADOW_FILE_FNC:
	{
				// 获取返回缓冲区
				OutBuffer = Irp->AssociatedIrp.SystemBuffer;

				NeedLength = ServiceTableShadow.NumberOfService * sizeof(ULONG);

				if (OutBuffer)
				{
					if (MmIsAddressValid(ServiceTableShadow.FileServiceTable))
					{
						RtlCopyMemory(OutBuffer, ServiceTableShadow.FileServiceTable, NeedLength);
					}
				}

				Status = STATUS_SUCCESS;

				break;

	}




		default:
			Status = STATUS_INVALID_VARIANT;
	
	}




	//--------------------------------------------------------------------------------
	//
	//设置Irp状态信息
	//
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = NeedLength;

	//
	//返回处理Irp
	//
	IoCompleteRequest(Irp, 0);

	//
	//return
	//
	return Status;
}


//
//驱动入口函数
//

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{

	//
	//Entry Driver Entry 
	//
	DbgPrint("Entry Driver Entry \n");


	NTSTATUS Status;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING DestinationString;
	UNICODE_STRING SymbolicLinkName;
	


	//
	//设置派遣函数
	//
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
	pDriverObject->DriverUnload = DriverUnload;



	//初始化设备名称
	RtlInitUnicodeString(&DestinationString, L"\\Device\\Excalibur");
	//创建设备
	Status = IoCreateDevice(pDriverObject, 0, &DestinationString, FILE_DEVICE_UNKNOWN, 0, 0, &pDeviceObject);


	pDriverObject->Flags |= DO_BUFFERED_IO;

	//Check Result
	if (NT_SUCCESS(Status))
	{
		//初始化符号链接
		RtlInitUnicodeString(&SymbolicLinkName, L"\\??\\Excalibur");
		//创建符号链接
		Status = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);

		if (NT_SUCCESS(Status))
		{
			//
			//一切准备就绪,可以初始化某些数据
			//

			NtEnumeServiceTable(&ServiceTable);
			NtEnumeServiceTableShadow(&ServiceTableShadow);


			//test
			_asm{
				int 3;
			}
			PVOID NewKernel = NULL;
			NtHeavyloadKernel(&NewKernel);
			NtFixKiFastCallEntry(NULL);
		}
		else
		{
			//
			//创建符号链接失败
			//

			//删除设备对象
			IoDeleteDevice(pDeviceObject);

		}

	}


	return Status;
	
	
}





