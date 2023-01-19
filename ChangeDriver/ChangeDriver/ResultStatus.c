#include <ResultStatus.h>



//
//¥Ú”°¥ÌŒÛ–≈œ¢
//
ULONG RstatusPrint(ULONG StatusCode)
{
	//trace
	switch (StatusCode)
	{

		//PeAnalysis
		case PE_STATUS_INVALID_PARAMETE:
		{
			KdPrint(("PE_STATUS_INVALID_PARAMETE\n"));
			break;

		}

		case PE_STATUS_RESULT_SUCCESS:
		{
			KdPrint(("PE_STATUS_RESULT_SUCCESS\n"));
			break;
		}

		case PE_STATUS_RESULT_ERROR:
		{
			KdPrint(("PE_STATUS_RESULT_ERROR\n"));
			break;
		}
		
		case PE_STATUS_MALLOCPOOL_ERROR:
		{
			KdPrint(("PE_STATUS_MALLOCPOOL_ERROR\n"));
			break;
		}
		case PE_STATUS_SEARCHEXPORT_ERROR:
		{
			 KdPrint(("PE_STATUS_SEARCHEXPORT_ERROR\n"));
			 break;
		}


			
		//DelayCall
		case DC_STATUS_INVALID_PARAMETE:
		{
			 KdPrint(("DC_STATUS_INVALID_PARAMETE\n"));
			 break;
		}
		case DC_STATUS_RESULT_SUCCESS:
		{
			 KdPrint(("DC_STATUS_RESULT_SUCCESS\n"));
			 break;
		}
		case DC_STATUS_RESULT_ERROR:
		{
			 KdPrint(("DC_STATUS_RESULT_ERROR\n"));
			 break;
		}
		
		//NtAnalysis
		case NT_STATUS_INVALID_PARAMETE:
		{
			KdPrint(("NT_STATUS_INVALID_PARAMETE\n"));
			break;
		}
		case NT_STATUS_RESULT_SUCCESS:
		{
			 KdPrint(("NT_STATUS_RESULT_SUCCESS\n"));
			 break;
		}
		case NT_STATUS_RESULT_ERROR:
		{
			 KdPrint(("NT_STATUS_RESULT_ERROR\n"));
			 break;
		}

		case NT_STATUS_MALLOCPOOL_ERROR:
		{
			 KdPrint(("NT_STATUS_MALLOCPOOL_ERROR\n"));
			 break;
		}
		case NT_STATUS_OPENFILE_ERROR:
		{
			 KdPrint(("NT_STATUS_OPENFILE_ERROR\n"));
			 break;
		}
		case NT_STATUS_GETFILESIZE_ERROR:
		{
			 KdPrint(("NT_STATUS_GETFILESIZE_ERROR\n"));
			 break;
		}
		case NT_STATUS_READFILE_ERROR:
		{
			 KdPrint(("NT_STATUS_READFILE_ERROR\n"));
			 break;
		}
		case NT_STATUS_GETKERNELBASE_ERROR:
		{
			 KdPrint(("NT_STATUS_GETKERNELBASE_ERROR\n"));
			 break;
		}

		//Hook
		case HK_STATUS_INVALID_PARAMETE:
		{
			 KdPrint(("HK_STATUS_INVALID_PARAMETE\n"));
			 break;

		}

		case HK_STATUS_RESULT_SUCCESS:
		{
			 KdPrint(("HK_STATUS_RESULT_SUCCESS\n"));
			 break;
		}

		case HK_STATUS_RESULT_ERROR:
		{
			 KdPrint(("HK_STATUS_RESULT_ERROR\n"));
			 break;
		}
			
		default:
			break;
	}
	return 0;
}

