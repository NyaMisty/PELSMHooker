// https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

const ULONG PATCH_OFFSET = 0x1BEEB;

int doHookLsm(HMODULE hLSMMod, DWORD processID)
{
	HANDLE hProcess;
	// Print the process identifier.
	printf("\nHooking LSM in process: %u...\n", processID);

	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);
	if (NULL == hProcess) {
		_tprintf(TEXT("Failed to open process"));
		return 1;
	}

	// Get a list of all the modules in this process.
	unsigned char IsLoggedonStateBuf[10];
	SIZE_T readed = 0;
	if (!ReadProcessMemory(hProcess, (char *)hLSMMod + PATCH_OFFSET, IsLoggedonStateBuf, sizeof(IsLoggedonStateBuf), &readed) || readed < sizeof(IsLoggedonStateBuf)) {
		_tprintf(TEXT("Failed to read process memory"));
		return CloseHandle(hProcess), 1;
	}

	_tprintf(_T("Target location's original data: \n"));
	for (int i = 0; i < sizeof(IsLoggedonStateBuf); i++) {
		_tprintf(_T("%02x "), IsLoggedonStateBuf[i]);
	}
	_tprintf(_T("\n"));

	// assert
	if (IsLoggedonStateBuf[0] != 0xE8 || IsLoggedonStateBuf[5] != 0x85 || IsLoggedonStateBuf[6] != 0xC0) {
		_tprintf(TEXT("Target addr is not 'call XXX; test eax, eax', aborting"));
		return CloseHandle(hProcess), 1;
	}

	unsigned char PatchBuf[5] = {
		0xb8, 0x01, 0x00, 0x00, 0x00 // mov eax, 1
	};

	// make it writable
	DWORD oldProt = 0;
	if (!VirtualProtectEx(hProcess, (char*)hLSMMod + PATCH_OFFSET, sizeof(PatchBuf), PAGE_EXECUTE_READWRITE, &oldProt)) {
		_tprintf(TEXT("Failed to unprotect process memory"));
		return CloseHandle(hProcess), 1;
	}

	// do the patch
	SIZE_T written = 0;
	if (!WriteProcessMemory(hProcess, (char*)hLSMMod + PATCH_OFFSET, PatchBuf, sizeof(PatchBuf), &written) || written < sizeof(PatchBuf)) {
		_tprintf(TEXT("Failed to write process memory"));
		return CloseHandle(hProcess), 1;
	}

	// revert it back
	if (!VirtualProtectEx(hProcess, (char*)hLSMMod + PATCH_OFFSET, sizeof(PatchBuf), oldProt, &oldProt)) {
		_tprintf(TEXT("Failed to re-protect process memory"));
		return CloseHandle(hProcess), 1;
	}

	// Release the handle to the process.
	CloseHandle(hProcess);
	return 0;
}

bool handleProcess(DWORD processID) {
	bool ret = false;
	
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hBaseMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hBaseMod, sizeof(hBaseMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hBaseMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));

			_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

			if (_tcsicmp(szProcessName, _T("svchost.exe")) == 0) {
				HMODULE hMods[1024];
				if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
				{
					for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
					{
						TCHAR szModName[MAX_PATH];

						// Get the full path to the module's file.

						if (GetModuleBaseName(hProcess, hMods[i], szModName,
							sizeof(szModName) / sizeof(TCHAR)))
						{
							_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
							if (_tcsicmp(szModName, _T("lsm.dll")) == 0) {
								_tprintf(TEXT("Found svchost with lsm dll (Base: %016llx PID: %u)\n"), hMods[i], processID);
								doHookLsm(hMods[i], processID);
								ret = true;
								break;
							}
						}
					}
				}
			}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);
	return ret;
}


int main(void)
{

	unsigned int i;

	// Get the list of process identifiers.

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return 1;
	}

	PROCESSENTRY32 pe32;

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		_tprintf(TEXT("Process32First")); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return 1;
	}
	
	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		if (handleProcess(pe32.th32ProcessID))
			break;

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return 0;
}