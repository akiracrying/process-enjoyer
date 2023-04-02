
#include "info_getter.h"

processenjoyer::processenjoyer(QWidget* parent)
    : QMainWindow(parent)
{

    ui.setupUi(this);
    QLocale curLocale(QLocale("ru_RU"));
    QLocale::setDefault(curLocale);
    setlocale(LC_ALL, "");

    wchar_t buffer[1024];

    DWORD dwRead;
    DWORD dwWritten;
    DWORD dwTmp = 0;
    LPCWSTR message = { 0 };
    HANDLE hPipe;
    process Temp = { 0 };
   // Temp.procDescryption = new wchar_t[MAX_NAME_LENGTH];

    int err = 0;

    hPipe = CreateFile(TEXT("\\\\.\\pipe\\Pipe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE){

        char* wcharConverter;
        for (size_t row = 0; row < 300 ; row++) {
            if (ReadFile(hPipe, &Temp, sizeof(Temp), &dwRead, NULL) != FALSE)
            {
                WriteFile(hPipe, &Temp, sizeof(Temp), &dwWritten, NULL);
            }
            //getProcessInfo(hPipe, &err, &Temp);
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
                //wcharConverter = new char[sizeof(Temp.procDescryption)];
                //wcstombs(wcharConverter, Temp.procDescryption, sizeof(Temp.procDescryption));
                //ui.tableWidget->setItem(row, 6,
                //    new QTableWidgetItem(
                //        wcharConverter
                //    )
                //);
                //delete[] wcharConverter;
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

    //delete[] Temp.procDescryption;
}


processenjoyer::~processenjoyer()
{

}
