#include <Ntifs.h>
#include <PeAnalysis.h>
#include <NtAnalysis.h>
#include <NtProcess.h>
#include <Hook.h>
#include <Excalibur.h>

#pragma once 




//ȫ�ֱ��� 

SERVICETABLE ServiceTable;
SERVICETABLE_SHADOW ServiceTableShadow;










//
//��������
//


//
//����ж��
//
VOID DriverUnload(PDRIVER_OBJECT pDriverObject);

//
//�������
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);

//
//��ǲ���� Create And Close
//

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//
//��ǲ���� IoControl
//


NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

//
//Ԥ����
//


#pragma alloc_text(INT,DriverEntry)
#pragma alloc_text (PAGED,DispatchCreateClose)
#pragma alloc_text (PAGED,DispatchIoControl)


//
//����ж������
//

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{

	DbgPrint("Entry unload\n");

	UNICODE_STRING SymbolicLinkName;

	//
	//����ж����������
	//

	NtDeleteServiceTable(&ServiceTable);
	NtDelectServiceTableShadow(&ServiceTableShadow);
	NtRestoreKiFastCallEntry();

	//
	//����ж�ش���
	//
	RtlInitUnicodeString(&SymbolicLinkName, L"\\??\\Excalibur");

	//ɾ����������
	IoDeleteSymbolicLink(&SymbolicLinkName);

	//ɾ����������
	IoDeleteDevice(pDriverObject->DeviceObject);



	
}


//
//Irp->DispatchCreateClose
//
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

	//
	//����Irp״̬��Ϣ
	//
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	//
	//���ش���Irp
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
	//���⿪ʼ����Irp
	//
	//--------------------------------------------------------------------------------
	
	NTSTATUS Status;
	PIO_STACK_LOCATION Stack = NULL;


	ULONG Code = 0; //������
	ULONG NeedLength = 0; // ʵ�ʲ�������
	ULONG InBufferLength = 0; //���뻺��������
	ULONG OutBufferLength = 0; //�������������
	
	PVOID InBuffer = NULL;
	PVOID OutBuffer = NULL;
	ULONG Value = 0;
	PVOID Table = NULL;
	PVOID Map = NULL;
	//��ȡ�豸ջ
	Stack = IoGetCurrentIrpStackLocation(Irp);
	//��ȡ���뻺������С
	InBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
	//��ȡ�����������С
	OutBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	//��ȡ������
	Code = Stack->Parameters.DeviceIoControl.IoControlCode;

	
	//
	//�����������
	//

	switch (Code) //0x800 ~ 0xFFF
	{
	case CTL_CODE_GET_SERVICETABLE_NUMBER:
		{
				 //��ȡ���ػ�����
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
					 //������������
					 if (OutBuffer)
					 {
						 RtlCopyMemory(OutBuffer, &Number, NeedLength);
					 }
									 
				 }

				 break;

		}


	case CTL_CODE_GET_SERVICETABLE_FNC_NAME: //Test
		{				
			
				//��ȡ���ػ�����
				OutBuffer = Irp->AssociatedIrp.SystemBuffer;

				

				//��ȡMap
				Map = ExGetServiceTableFncName(&NeedLength, &ServiceTable);

				if (Map == NULL)
				{
					Status = STATUS_INVALID_VARIANT;
					break;
				}
				else{
					Status = STATUS_SUCCESS;

					//������������
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
					 // ��ȡ���ػ�����
					OutBuffer = Irp->AssociatedIrp.SystemBuffer;


					ULONG Number = ExGetServiceTableNumber(&ServiceTable);

					NeedLength = Number*sizeof(PVOID);

					//��ȡMap
					Map = ExGetServiceTableMemFnc();

					if (Map == NULL)
					{
							Status = STATUS_INVALID_VARIANT;
							break;
					}
					else
					{
						  Status = STATUS_SUCCESS;

						  ///������������
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
				// ��ȡ���ػ�����
				OutBuffer = Irp->AssociatedIrp.SystemBuffer;

				ULONG Number = ExGetServiceTableNumber(&ServiceTable);

				NeedLength = Number*sizeof(PVOID);

				//��ȡMap
				Table = ExGetServiceTableFileFnc();

				if (Table == NULL)
				{
					Status = STATUS_INVALID_VARIANT;
					break;
				}
				else
				{
					Status = STATUS_SUCCESS;

					///������������
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
				// ��ȡ���ػ�����
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

					///������������
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
				// ��ȡ���ػ�����
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
	//����Irp״̬��Ϣ
	//
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = NeedLength;

	//
	//���ش���Irp
	//
	IoCompleteRequest(Irp, 0);

	//
	//return
	//
	return Status;
}


//
//������ں���
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
	//������ǲ����
	//
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
	pDriverObject->DriverUnload = DriverUnload;



	//��ʼ���豸����
	RtlInitUnicodeString(&DestinationString, L"\\Device\\Excalibur");
	//�����豸
	Status = IoCreateDevice(pDriverObject, 0, &DestinationString, FILE_DEVICE_UNKNOWN, 0, 0, &pDeviceObject);


	pDriverObject->Flags |= DO_BUFFERED_IO;

	//Check Result
	if (NT_SUCCESS(Status))
	{
		//��ʼ����������
		RtlInitUnicodeString(&SymbolicLinkName, L"\\??\\Excalibur");
		//������������
		Status = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);

		if (NT_SUCCESS(Status))
		{
			//
			//һ��׼������,���Գ�ʼ��ĳЩ����
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
			//������������ʧ��
			//

			//ɾ���豸����
			IoDeleteDevice(pDeviceObject);

		}

	}


	return Status;
	
	
}





