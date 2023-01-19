#include <Excalibur.h>





//
//��ȡ�ڴ�ServiceTableName
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
//��ȡ�ڴ�ServiceTableFnc
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
//��ȡ�ļ�ServiceTableFnc
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
//��ȡServiceTableFncNumber
//
ULONG ExGetServiceTableNumber(IN PSERVICETABLE pServiceTable)
{
	return pServiceTable->NumberOfService;
}

//
//��ȡServiceTableShadowFncNumber
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
//��ȡ�ļ� ServiceTableShadow
//
PVOID ExGetServiceTableShadowFileFnc()
{
	ULONG Count;
	return NtGetShadowServiceFormFile(&Count);
}

//
//��ȡ�ڴ� ServiceTableShadow
//
PVOID ExGetServiceTableShadowMemFnc()
{
	ULONG Count;
	return NtGetShadowServiceFormMem(&Count);
}