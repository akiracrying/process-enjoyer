
#include "info_getter.h"

processenjoyer::processenjoyer(QWidget* parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);


    wchar_t buffer[1024];

    DWORD dwTmp = 0;
    LPCWSTR message = { 0 };
    HANDLE hPipe;
    process Temp = { 0 };
    int err;

    hPipe = CreateFile(TEXT("\\\\.\\pipe\\Pipe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE){

        char* wcharConverter;
        for (size_t row = 0; row < 300 ; row++) {
            
            getProcessInfo(hPipe, &err, &Temp);
            if (err != 1) {
                ui.tableWidget->insertRow(ui.tableWidget->rowCount());
     
                ui.tableWidget->setItem(row, 0,
                    new QTableWidgetItem(std::to_string(Temp.PID).c_str()));
                wcharConverter = new char[sizeof(Temp.processName)];
                wcstombs(wcharConverter, Temp.processName, sizeof(Temp.processName));
                ui.tableWidget->setItem(row, 1,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                wcharConverter = new char[sizeof(Temp.pathProcessExe)];
                wcstombs(wcharConverter, Temp.pathProcessExe, sizeof(Temp.pathProcessExe));
                ui.tableWidget->setItem(row, 2,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                wcharConverter = new char[sizeof(Temp.processOwner)];
                wcstombs(wcharConverter, Temp.processOwner, sizeof(Temp.processOwner));
                ui.tableWidget->setItem(row, 3,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                wcharConverter = new char[sizeof(Temp.SID)];
                wcstombs(wcharConverter, Temp.SID, sizeof(Temp.SID));
                ui.tableWidget->setItem(row, 4,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                wcharConverter = new char[sizeof(Temp.procType)];
                wcstombs(wcharConverter, Temp.procType, sizeof(Temp.procType));
                ui.tableWidget->setItem(row, 5,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                wcharConverter = new char[sizeof(Temp.integrityLevel)];
                wcstombs(wcharConverter, Temp.integrityLevel, sizeof(Temp.integrityLevel));
                ui.tableWidget->setItem(row, 6,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                ui.tableWidget->setItem(row, 7,
                    new QTableWidgetItem(std::to_string(Temp.CLR).c_str())
                );
                ui.tableWidget->setItem(row, 8,
                    new QTableWidgetItem(std::to_string(Temp.ASLR).c_str())
                );
                ui.tableWidget->setItem(row, 9,
                    new QTableWidgetItem(std::to_string(Temp.DEP).c_str())
                );
                wcharConverter = new char[sizeof(Temp.aslrDetails)];
                wcstombs(wcharConverter, Temp.aslrDetails, sizeof(Temp.aslrDetails));
                ui.tableWidget->setItem(row, 10,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                wcharConverter = new char[sizeof(Temp.depDetails)];
                wcstombs(wcharConverter, Temp.depDetails, sizeof(Temp.depDetails));
                ui.tableWidget->setItem(row, 11,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                wcharConverter = new char[sizeof(Temp.parentName)];
                wcstombs(wcharConverter, Temp.parentName, sizeof(Temp.parentName));
                ui.tableWidget->setItem(row, 12,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                ui.tableWidget->setItem(row, 13,
                    new QTableWidgetItem(std::to_string(Temp.parentPID).c_str()));
                //ui.tableWidget->selectColumn(DLL);
            }
        }
        CloseHandle(hPipe);
    }
}


processenjoyer::~processenjoyer()
{

}
