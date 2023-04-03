#include "info_getter.h"

void getProcessInfo(HANDLE hPipe, int*err, process* Temp) {
    DWORD dwRead;
    DWORD dwWritten;

    if (ReadFile(hPipe, Temp, sizeof(Temp), &dwRead, NULL) != FALSE)
    {
        WriteFile(hPipe, Temp, sizeof(Temp), &dwWritten, NULL);
    }
    else {
        *err = 1;
    }
}

void fillTableInfo() {

}