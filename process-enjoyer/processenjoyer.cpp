
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
        for (size_t row = 0;  ; row++) {
            int col = 0;
            if (ReadFile(hPipe, &Temp, sizeof(Temp), &dwRead, NULL) != FALSE)
            {
                WriteFile(hPipe, &Temp, sizeof(Temp), &dwWritten, NULL);
            }
            else {
                break;
            }
            //getProcessInfo(hPipe, &err, &Temp);

            QByteArray encodedString;
            auto toSysEnc = QStringDecoder(QStringDecoder::System);

            if (err != 1) {
                ui.tableWidget->insertRow(ui.tableWidget->rowCount());
    
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(Temp.PID).c_str()));

                wcharConverter = new char[sizeof(Temp.processName)];
                wcstombs(wcharConverter, Temp.processName, sizeof(Temp.processName));
                encodedString = wcharConverter;
                QString string = toSysEnc(encodedString);
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        string
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.pathProcessExe)];
                wcstombs(wcharConverter, Temp.pathProcessExe, sizeof(Temp.pathProcessExe));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.processOwner)];
                wcstombs(wcharConverter, Temp.processOwner, sizeof(Temp.processOwner));
                encodedString = wcharConverter;
                string = toSysEnc(encodedString);
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        string
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.SID)];
                wcstombs(wcharConverter, Temp.SID, sizeof(Temp.SID));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.procType)];
                wcstombs(wcharConverter, Temp.procType, sizeof(Temp.procType));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.integrityLevel)];
                wcstombs(wcharConverter, Temp.integrityLevel, sizeof(Temp.integrityLevel));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.procDescryption)];
                wcstombs(wcharConverter, Temp.procDescryption, sizeof(Temp.procDescryption));
                encodedString = wcharConverter;
                string = toSysEnc(encodedString);
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        string
                    )
                );
                delete[] wcharConverter;
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(Temp.CLR).c_str())
                );
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(Temp.ASLR).c_str())
                );
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(Temp.DEP).c_str())
                );

                wcharConverter = new char[sizeof(Temp.aslrDetails)];
                wcstombs(wcharConverter, Temp.aslrDetails, sizeof(Temp.aslrDetails));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.depDetails)];
                wcstombs(wcharConverter, Temp.depDetails, sizeof(Temp.depDetails));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(Temp.parentName)];
                wcstombs(wcharConverter, Temp.parentName, sizeof(Temp.parentName));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(Temp.parentPID).c_str()));

                QPushButton* DLLButton = new QPushButton("DLL_LIST");
                ui.tableWidget->setCellWidget(row, col++,
                    DLLButton
                );

                 QDialog* DllDialog = new QDialog;
                 Ui_Dialog* DllUi = new Ui_Dialog;
                 DllUi->tableWidget = new QTableWidget[sizeof(Temp.processDllsName + 10)];

                 int dll_col = 0, dll_row = 0;
                 for (int dll_count = 0; ; dll_count++) {
                     wchar_t symb = Temp.processDllsName[dll_count][0];
                     wchar_t nil = { '\0' };
                     if (symb == nil) {
                         break;
                     }
                     wcharConverter = new char[sizeof(Temp.processDllsName[dll_count])];
                     wcstombs(wcharConverter, Temp.processDllsName[dll_count], sizeof(Temp.processDllsName[dll_count]));

                     DllUi->tableWidget->setItem(dll_row++, dll_col,
                         new QTableWidgetItem(
                             wcharConverter
                         )
                     );
                     delete[] wcharConverter;
                 }

                 DllUi->setupUi(DllDialog);
                 connect(DllUi->okButton, SIGNAL(clicked()), DllDialog, SLOT(close()));


                 //connect(DLLButton, SIGNAL(clicked()), this, SLOT(DllDialog->show()));
                 connect(DLLButton, SIGNAL(clicked()), DllDialog, SLOT(exec()));

            }
        }
        CloseHandle(hPipe);
    }

    //delete[] Temp.procDescryption;
}


processenjoyer::~processenjoyer()
{

}
