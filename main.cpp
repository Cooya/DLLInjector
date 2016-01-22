#include <windows.h>
#include <iostream>
#include <cstdio>
#include <tlhelp32.h>
#include <unistd.h>

HANDLE retrieveProcessId(char *processName) {
    HANDLE hProcess = NULL;
    PROCESSENTRY32 entry;
    entry.dwFlags = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(Process32First(snapshot,&entry) == true)
        while(Process32Next(snapshot,&entry) == true)
            if(_stricmp(entry.szExeFile, processName) == 0)
                hProcess = OpenProcess(PROCESS_ALL_ACCESS,false,entry.th32ProcessID);
    CloseHandle(snapshot);
    return hProcess;
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        std::cout << "Missing arguments for injector.\n";
        return 0;
    }

    char dllPath[1024];
    if(getcwd(dllPath, sizeof(dllPath)) == NULL)
       std::cout << "Impossible to retrieve the current working directory.\n";

    char* dllName = argv[1];
    strcat(dllPath, "\\");
    strcat(dllPath, dllName);
    if(access(dllName, F_OK) == -1) {
        std::cout << "DLL not found.\n";
        return 0;
    }

    char* processName = argv[2];
    void* pLoadLibrary = (void*)GetProcAddress(GetModuleHandle("kernel32"),"LoadLibraryA");
    HANDLE hProcess = NULL;
    STARTUPINFOA startupInfo;
    ZeroMemory(&startupInfo,sizeof(startupInfo));

    std::cout << "Getting process ID of process \"" << processName << "\"...\n";
    if(!(hProcess = retrieveProcessId(processName))) {
        std::cout << "Process ID unknown. GetLastError() = " << GetLastError();
        return 0;
    }

    std::cout << "Allocating virtual memory...\n";
    void* pReservedSpace = VirtualAllocEx(hProcess,NULL,strlen(dllPath),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    if(!pReservedSpace) {
        std::cout << "Could not allocate virtual memory. GetLastError() = " << GetLastError();
        return 0;
    }

    std::cout << "Writing process memory...\n";
    if(!WriteProcessMemory(hProcess,pReservedSpace,dllPath,strlen(dllPath),NULL)) {
        std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError();
        return 0;
    }

    std::cout << "Creating remote thread...\n";
    HANDLE hThread = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)pLoadLibrary,pReservedSpace,0,NULL);
    if(!hThread) {
        std::cout << "Unable to create the remote thread. GetLastError() = " << GetLastError();
        return 0;
    }

    std::cout << "Thread created.\n";

    WaitForSingleObject(hThread,INFINITE);
    VirtualFreeEx(hProcess,pReservedSpace,strlen(dllPath),MEM_COMMIT);
    CloseHandle(hProcess);

    std::cout << "Done.";
    return 0;
}

/*
std::cout << "LoadLibrary:0x" << std::hex << pLoadLibrary << std::dec << "\nCreating process 'TargetApplication.exe' ... \n";
if(!CreateProcessA(0,"TargetApplication.exe",0,0,1,CREATE_NEW_CONSOLE,0,0,&startupInfo,&processInformation)) {
    std::cout << "Could not run 'TargetApplication.exe'. GetLastError() = " << GetLastError();
    return 0;
}
*/
