#ifndef INJECTOR_H
#define INJECTOR_H

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <errno.h>

/*Function Pointer Struct*/
typedef struct manual_Mapping_t manual_Mapping_t;

/*Function Dec.*/
int ManualMap(HANDLE hProc, const char* szDllFile);
void __stdcall Shellcode(LPVOID ptr);



#endif // !INJECTOR_H

