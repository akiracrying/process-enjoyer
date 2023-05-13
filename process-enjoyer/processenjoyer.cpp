
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
    process proc_data = { 0 };
   // Temp.procDescryption = new wchar_t[MAX_NAME_LENGTH];

    int err = 0;

    hPipe = CreateFile(TEXT("\\\\.\\pipe\\Pipe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE){

        char* wcharConverter;
        for (size_t row = 0;  ; row++) {
            int col = 0;
            if (ReadFile(hPipe, &proc_data, sizeof(proc_data), &dwRead, NULL) != FALSE)
            {
                WriteFile(hPipe, &proc_data, sizeof(proc_data), &dwWritten, NULL);
            }
            else {
                break;
            }

            QByteArray encodedString;
            auto toSysEnc = QStringDecoder(QStringDecoder::System);

            if (err != 1) {
                ui.tableWidget->insertRow(ui.tableWidget->rowCount());
    
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(proc_data.PID).c_str()));

                wcharConverter = new char[sizeof(proc_data.processName)];
                wcstombs(wcharConverter, proc_data.processName, sizeof(proc_data.processName));
                encodedString = wcharConverter;
                QString string = toSysEnc(encodedString);
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        string
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.pathProcessExe)];
                wcstombs(wcharConverter, proc_data.pathProcessExe, sizeof(proc_data.pathProcessExe));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.processOwner)];
                wcstombs(wcharConverter, proc_data.processOwner, sizeof(proc_data.processOwner));
                encodedString = wcharConverter;
                string = toSysEnc(encodedString);
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        string
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.SID)];
                wcstombs(wcharConverter, proc_data.SID, sizeof(proc_data.SID));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.procType)];
                wcstombs(wcharConverter, proc_data.procType, sizeof(proc_data.procType));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.integrityLevel)];
                wcstombs(wcharConverter, proc_data.integrityLevel, sizeof(proc_data.integrityLevel));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.procDescryption)];
                wcstombs(wcharConverter, proc_data.procDescryption, sizeof(proc_data.procDescryption));
                encodedString = wcharConverter;
                string = toSysEnc(encodedString);
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        string
                    )
                );
                delete[] wcharConverter;
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(proc_data.CLR).c_str())
                );
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(proc_data.ASLR).c_str())
                );
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(proc_data.DEP).c_str())
                );

                wcharConverter = new char[sizeof(proc_data.aslrDetails)];
                wcstombs(wcharConverter, proc_data.aslrDetails, sizeof(proc_data.aslrDetails));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.depDetails)];
                wcstombs(wcharConverter, proc_data.depDetails, sizeof(proc_data.depDetails));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                wcharConverter = new char[sizeof(proc_data.parentName)];
                wcstombs(wcharConverter, proc_data.parentName, sizeof(proc_data.parentName));
                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;

                ui.tableWidget->setItem(row, col++,
                    new QTableWidgetItem(std::to_string(proc_data.parentPID).c_str()));

                QPushButton* DLLButton = new QPushButton("DLL_LIST");
                ui.tableWidget->setCellWidget(row, col++,
                    DLLButton
                );

                QDialog* DllDialog = new QDialog(this);
                QTableWidget* table = new QTableWidget(DllDialog);
                Ui_Dialog* DllUi = new Ui_Dialog;
                QHBoxLayout* layout = new QHBoxLayout(DllDialog);

                table->setFixedWidth(700);
                table->insertColumn(0);
                table->setHorizontalHeaderLabels({ "DLL NAME" });
                table->setColumnWidth(0, 600);

                int dll_col = 0;
                for (int dll_count = 0; ; dll_count++) {
                    dll_col = 0;
                    table->insertRow(table->rowCount());

                    wchar_t symb = proc_data.processDllsName[dll_count][0];
                    wchar_t nil = { '\0' };
                    if (symb == nil) {
                        break;
                    }

                    //table->setItem(dll_count, dll_col++,
                    //    new QTableWidgetItem(std::to_string(dll_count).c_str()));

                    wcharConverter = new char[sizeof(proc_data.processDllsName[dll_count])];
                    wcstombs(wcharConverter, proc_data.processDllsName[dll_count], sizeof(proc_data.processDllsName[dll_count]));

                    table->setItem(dll_count, dll_col++,
                        new QTableWidgetItem(
                            wcharConverter
                        )
                    );
                    delete[] wcharConverter;
                }
                setContentsMargins(20, 0, 0, 0);
                layout->addWidget(table, 0, Qt::AlignLeft);
                DllUi->setupUi(DllDialog);
                connect(DllUi->okButton, SIGNAL(clicked()), DllDialog, SLOT(close()));
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
