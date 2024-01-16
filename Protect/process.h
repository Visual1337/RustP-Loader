#include <TlHelp32.h>
#include <wtypes.h>

int getnigga(const char* process_name)
{
	
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	
	if (!Process32First(snapshot, &entry) == TRUE)
	{
		return 0;
	}


	while (Process32Next(snapshot, &entry) == TRUE)
	{
		if (strcmp(entry.szExeFile, process_name) == 0)
		{
			return (int)entry.th32ProcessID;
		}
	}


	return 0;
}