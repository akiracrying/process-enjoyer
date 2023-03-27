#include "info_getter.h"

PROCESS getProcessInfo() {
    PROCESS INFO = {
        1237,
        L"explorer.exe",
        L"C:\\Windows\\explorer.exe",
        L"SYSTEM",
        L"S-1-5-1-18",
        L"HUINYA",
        L"INTEGRITY",
        false,
        false,
        false,
        L"ASLR_DET",
        L"DERP_DET",
        L"BARAK_OBAMA",
        228,
        {L"DAS",L"ASD"},
    };
    return INFO;
}

