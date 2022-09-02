#include "injection.h"

const char szDllFile[] = "C:\\DllToInject.dll";			//Path of Dll to inject
const char procHash[] = "Process.exe";				//Target Process

int main() {
	PROCESSENTRY32 PE32;	
	PE32.dwSize = sizeof(PE32);	
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
	if (hSnap == INVALID_HANDLE_VALUE){
		printf("CreateToolHelp32Snapshot Failed: %d\n",errno);
		system("PAUSE");
		return 0;
	}
	DWORD PID = 0;	
	BOOL bRet = Process32First(hSnap, &PE32);	
	while (bRet) {
		if (!(strcmp(procHash, PE32.szExeFile))) {
			PID = PE32.th32ProcessID;	
			printf("[+]PID Found: %s | PID: %d\n", PE32.szExeFile, PID);
			break;
		}
		bRet = Process32Next(hSnap, &PE32);	
	}
	CloseHandle(hSnap);	

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);	
	if (!hProc) {	
		printf("[!]OpenProcess Failed: %d\n",errno);
		system("PAUSE");
		return 0;
	}
	if (ManualMap(hProc, szDllFile)) {	
		CloseHandle(hProc);r
		printf("[!]Something went wrong...\n");
		system("PAUSE");
		return 0;
	}
	CloseHandle(hProc);	
	return 0;								
}

