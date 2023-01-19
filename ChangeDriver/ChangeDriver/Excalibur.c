#include <Excalibur.h>





//
//获取内存ServiceTableName
//

PVOID ExGetServiceTableFncName(OUT PULONG MapSize,IN PSERVICETABLE pServiceTable)
{


	if (!MmIsAddressValid(pServiceTable))
	{
		return NULL;
	}


	PVOID Map = NULL;

	PANSI_STRING_LIST_HEADER ListHead = pServiceTable->NameList;


	Map = AnsiListToMapping(ListHead, FALSE, MapSize);

	return Map;

}

//
//获取内存ServiceTableFnc
//
PVOID ExGetServiceTableMemFnc()

{
	ULONG Value;
	SERVICETABLE ServiceTable;

	Value = NtEnumeServiceTable(&ServiceTable);

	if (Value == 0)
	{
		DbgPrint("NtEnumeServiceTable Error\n");

		ServiceTable.FileServiceTable = NULL;
		ServiceTable.MemServiceTable = NULL;
		ServiceTable.NameList = NULL;
		ServiceTable.NumberOfService = 0;
	}

	ReleaseAnsiList(ServiceTable.NameList);
	ExFreePoolWithTag(ServiceTable.FileServiceTable, 1024);
	return ServiceTable.MemServiceTable;
}

//
//获取文件ServiceTableFnc
//

PVOID ExGetServiceTableFileFnc()
{
	ULONG Value;
	SERVICETABLE ServiceTable;

	Value = NtEnumeServiceTable(&ServiceTable);

	if (Value == 0)
	{
		DbgPrint("NtEnumeServiceTable Error\n");

		ServiceTable.FileServiceTable = NULL;
		ServiceTable.MemServiceTable = NULL;
		ServiceTable.NameList = NULL;
		ServiceTable.NumberOfService = 0;
	}

	ReleaseAnsiList(ServiceTable.NameList);
	ExFreePoolWithTag(ServiceTable.MemServiceTable, 1024);
	return ServiceTable.FileServiceTable;
}

//
//获取ServiceTableFncNumber
//
ULONG ExGetServiceTableNumber(IN PSERVICETABLE pServiceTable)
{
	return pServiceTable->NumberOfService;
}

//
//获取ServiceTableShadowFncNumber
//
ULONG ExGetServiceTableShadowNumber()
{
	PVOID Table = NULL;
	ULONG Number = 0;

	Table = NtGetShadowServiceFormFile(&Number);

	if (Table == NULL)
	{
		return 0;
	}

	if (MmIsAddressValid(Table))
	{
		ExFreePoolWithTag(Table, 1024);
	}

	return Number;
}


//
//获取文件 ServiceTableShadow
//
PVOID ExGetServiceTableShadowFileFnc()
{
	ULONG Count;
	return NtGetShadowServiceFormFile(&Count);
}

//
//获取内存 ServiceTableShadow
//
PVOID ExGetServiceTableShadowMemFnc()
{
	ULONG Count;
	return NtGetShadowServiceFormMem(&Count);
}