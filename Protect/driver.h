#pragma once
#include <Windows.h>
#include "../XorStr.h"
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

bool DriverCheck()
{

	LPVOID drivers[2048];
	DWORD cbNeeded;
	int cDrivers, i;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[2048];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (i = 0; i < cDrivers; i++)
		{
			if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				std::string strDriver = szDriver;
				if (strDriver.find(_xor("HttpDebug")) != std::string::npos)
				{
					return true;
				}
				if (strDriver.find(_xor("TitanHide")) != std::string::npos)
				{
					return true;
				}
				if (strDriver.find(_xor("SharpOD_Drv")) != std::string::npos)
				{
					return true;
				}

				if (strDriver.find(_xor("Scylla")) != std::string::npos)
				{
					return true;
				}
				if (strDriver.find(_xor("HTTPAnalyzerStdV7")) != std::string::npos)
				{
					return true;
				}
				if (strDriver.find(_xor("ScyllaHide")) != std::string::npos)
				{
					return true;
				}
			}
		}
	}
	return false;

}