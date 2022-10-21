#include "injection.h"

typedef struct manual_Mapping_t {
	HMODULE (WINAPI *f_LoadLibraryA)(const char*);                //Function pointer
	FARPROC (WINAPI *f_GetProcAddress)(HINSTANCE, const char*);   //Function Pointer
} manual_Mapping_t;

int ManualMap(HANDLE hProc, const char* szDllFile) {
/*Open DLL, move it into memory, close file*/
	FILE* dllFile;
	BYTE *dllBuff, *pTargetBase;
	long int dllFileSize;
	if (!(dllFile = fopen(szDllFile, "rb"))) {
		printf("[!]DLL file couldn't open: %d\n", errno);
		return 1;
	}
	if ((fseek(dllFile, 0, SEEK_END)) != 0) {
		printf("[!]Fseek Error: %d\n", errno);
		fclose(dllFile);
		return 1;
	}
	dllFileSize = ftell(dllFile);							
	rewind(dllFile);									
	dllBuff = (BYTE*)malloc(dllFileSize);					
	fread(dllBuff, sizeof(BYTE), dllFileSize + 1, dllFile);	
	fclose(dllFile);										

/*Error Handling / DLL File Checking*/
	PIMAGE_DOS_HEADER       dllDosHeaders	= dllBuff;
	PIMAGE_NT_HEADERS       dllNTHeaders	= dllBuff + dllDosHeaders->e_lfanew;		
	PIMAGE_OPTIONAL_HEADER  dllOptHeader	= &dllNTHeaders->OptionalHeader;
	PIMAGE_FILE_HEADER      dllFileHeader	= &dllNTHeaders->FileHeader;
	PIMAGE_SECTION_HEADER   dllSectHeader	= IMAGE_FIRST_SECTION(dllNTHeaders);

	if (dllDosHeaders->e_magic != 0x5A4D) {
		printf("[!]DOS Magic numbers wrong! Got %p, should be 0x4D5A\n", dllDosHeaders->e_magic);
		free(dllBuff);
		return 1;
	}
	if (dllNTHeaders->Signature != 0x4550) {
		printf("[!]NT signature wrong! Got %p, should be 0x4550\n", dllNTHeaders->Signature);
		free(dllBuff);
		return 1;
	}

/*Check File Archecture, Verify DLL will work*/
#ifdef _WIN64
	if (dllFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("[!]DLL not x64\n");
		free(dllBuff);
		return 1;
	}
#else
	if (dllFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		printf("[!]DLL not x86\n");
		free(dllBuff);
		return 1;
	}
#endif

/*Allocate Memory on target PID for DLL*/
	//Tries to allocate memory on target at ImageBase, if that doesn't work, allocate wherever. 
	if (!(pTargetBase = VirtualAllocEx(hProc, (VOID*)dllOptHeader->ImageBase, dllOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
		if (!(pTargetBase = VirtualAllocEx(hProc, NULL, dllOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
			printf("[!]Memory Allocation on Target failed: %d\n", GetLastError());
			free(dllBuff);
			return 1;
		}
	}
	//When importing DLLs, you only need entires that have data. Quick loop to only write valid entries
	for (UINT i = 0; i != dllFileHeader->NumberOfSections; ++i, ++dllSectHeader) {
		if (dllSectHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + dllSectHeader->VirtualAddress, dllBuff + dllSectHeader->PointerToRawData, dllSectHeader->SizeOfRawData, NULL)) {
				printf("[!]Can't map sections: %d\n", GetLastError());
				free(dllBuff);
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return 1;
			}
		}
	}
	/*Set up function pointers, write to target process*/
	manual_Mapping_t data;
	data.f_LoadLibraryA = LoadLibraryA;
	data.f_GetProcAddress = GetProcAddress;
	memcpy(dllBuff, &data, sizeof(manual_Mapping_t));						
	WriteProcessMemory(hProc, pTargetBase, dllBuff, 0x1000, NULL);			
  free(dllBuff);
	/*Allocate Memory for shellcode, write shellcode to target process*/
	void* pShellcode = VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		printf("[!]Memory Allocation failed (ex) %d\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return 1;
	}
	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, NULL);
	/*Start thread, wait for shellcode to finish*/
  HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)(pShellcode), pTargetBase, 0, NULL);
	if (!hThread) {
		if (GetLastError() == 5) {
			printf("[!]CreateRemoteThread Failed: Running injector as x32, Should be x64\n");
		}
		else {
			printf("[!]CreateRemoteThread failed: %d\n", GetLastError());
		}
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return 1;
	}
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	return 0;
}

/*Macro used to get the status of RELOC*/
#define RELOC_FLAG32(RelInfo) ((RelInfo>>0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo>>0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(BYTE* ptr) {
	if (!ptr) {
		return; //Something went wrong with our shellcode
	}

	//Struct Creations
	manual_Mapping_t		*data		= ptr;
	PIMAGE_DOS_HEADER		pDosHeaders	= ptr;
	PIMAGE_NT_HEADERS		pNTHeaders	= ptr + pDosHeaders->e_lfanew;
	PIMAGE_OPTIONAL_HEADER	pOptHeader	= &pNTHeaders->OptionalHeader;
	PIMAGE_FILE_HEADER		pFileHeader = &pNTHeaders->FileHeader;
	PIMAGE_SECTION_HEADER	pSectHeader = IMAGE_FIRST_SECTION(pNTHeaders);
	PIMAGE_BASE_RELOCATION	pRelocData	= ptr + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	//Function Pointers
	HMODULE	(WINAPI * _LoadLibraryA)(LPCSTR*);
	HMODULE	(WINAPI * _GetProcAddress)(HMODULE*, LPCSTR*);				
	BOOL	(WINAPI * _DllMain)(HINSTANCE*, DWORD, LPVOID*);

	_LoadLibraryA		= data->f_LoadLibraryA;
	_GetProcAddress		= data->f_GetProcAddress;
	_DllMain = ptr + pOptHeader->AddressOfEntryPoint;					
	

	//Check to see if the DLL loaded at prefered image base. If not, relocation is needed
	int subtractOrAdd = 0;
	BYTE* LocationDelta = NULL;
	if (ptr < pOptHeader->ImageBase) {			
		LocationDelta = pOptHeader->ImageBase - (DWORD)ptr;
	} 
	if (ptr > pOptHeader->ImageBase) {			
		LocationDelta = ptr - pOptHeader->ImageBase;
		subtractOrAdd = 1;
	}
/*Check to see if reloc is needed, if so reloc!*/
	if (LocationDelta) {
		if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) { 
			return;
		}
		while (pRelocData->VirtualAddress) { 
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);	/
			WORD* pRelativeInfo = pRelocData + 1;																
			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {																
					UINT_PTR* pPatch = (ptr + pRelocData->VirtualAddress) + ((*pRelativeInfo) & 0xFFF);			
					if (subtractOrAdd == 1) {																	
						*pPatch += (UINT_PTR)(LocationDelta);
					}
					else {
						*pPatch -= (UINT_PTR)(LocationDelta);
					}
				}
			}
			(BYTE*)pRelocData += pRelocData->SizeOfBlock;														
		}
	}
/*Get import list, import them using function pointers*/
	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		IMAGE_IMPORT_DESCRIPTOR* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(ptr + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {							
			char* szMod = (char*)(ptr + pImportDescr->Name);		
			HMODULE hDLL = _LoadLibraryA(szMod);
			//Get RVA for functions
			ULONG_PTR* pThunkRef = (ULONG_PTR*)(ptr + pImportDescr->OriginalFirstThunk);	
			ULONG_PTR* pFuncRef = (ULONG_PTR*)(ptr + pImportDescr->FirstThunk);					
			if (!pThunkRef) {
				pThunkRef = pFuncRef;
			}
				for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {

					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
						*pFuncRef = GetProcAddress_F(hDLL, (char*)(*pThunkRef & 0xFFFF));
					}
					else {
						PIMAGE_IMPORT_BY_NAME pImport = (IMAGE_IMPORT_BY_NAME*)(ptr + (*pThunkRef));
						*pFuncRef = GetProcAddress_F(hDLL, pImport->Name);
					}
				}
				++pImportDescr;
		}
	}
	/*Start dll through process_attach*/
	_DllMain(ptr, DLL_PROCESS_ATTACH, NULL);
}

