
#include "info_getter.h"


processenjoyer::processenjoyer(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    PROCESS *allProcess = new PROCESS;

    QModelIndex index;
    allProcess[0] = getProcessInfo();

    // For is needed
    ui.tableWidget->insertRow(ui.tableWidget->rowCount());
    char* wcharConverter;

    for (size_t i = PID; i < ui.tableWidget->colorCount(); i++)
    {
        switch (i) {
            case PID:
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(std::to_string(allProcess[0].PID).c_str()));
                break;
            case PROCESS_NAME:
                wcharConverter = new char[sizeof(allProcess[0].processName)];
                wcstombs(wcharConverter, allProcess[0].processName, sizeof(allProcess[0].processName));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case PATH:
                wcharConverter = new char[sizeof(allProcess[0].pathProcessExe)];
                wcstombs(wcharConverter, allProcess[0].pathProcessExe, sizeof(allProcess[0].pathProcessExe));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case OWNER:
                wcharConverter = new char[sizeof(allProcess[0].processOwner)];
                wcstombs(wcharConverter, allProcess[0].processOwner, sizeof(allProcess[0].processOwner));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case SID_NAME:
                wcharConverter = new char[sizeof(allProcess[0].SID)];
                wcstombs(wcharConverter, allProcess[0].SID, sizeof(allProcess[0].SID));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case TYPE:
                wcharConverter = new char[sizeof(allProcess[0].procType)];
                wcstombs(wcharConverter, allProcess[0].procType, sizeof(allProcess[0].procType));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case INT_LVL:
                wcharConverter = new char[sizeof(allProcess[0].integrityLevel)];
                wcstombs(wcharConverter, allProcess[0].integrityLevel, sizeof(allProcess[0].integrityLevel));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case CLR:
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(std::to_string(allProcess[0].CLR).c_str())
                );
                break;
            case ASLR:
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(std::to_string(allProcess[0].ASLR).c_str())
                );
                break;
            case DEP:
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(std::to_string(allProcess[0].DEP).c_str())
                );
                break;
            case ASLR_DET:
                wcharConverter = new char[sizeof(allProcess[0].aslrDetails)];
                wcstombs(wcharConverter, allProcess[0].aslrDetails, sizeof(allProcess[0].aslrDetails));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case DEP_DET:
                wcharConverter = new char[sizeof(allProcess[0].depDetails)];
                wcstombs(wcharConverter, allProcess[0].depDetails, sizeof(allProcess[0].depDetails));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case PARENT_NAME:
                wcharConverter = new char[sizeof(allProcess[0].parentName)];
                wcstombs(wcharConverter, allProcess[0].parentName, sizeof(allProcess[0].parentName));
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
                break;
            case PARENT_PID:
                ui.tableWidget->setItem(0, i,
                    new QTableWidgetItem(std::to_string(allProcess[0].parentPID).c_str()));
                break;
            case DLL:
                //todo
                break;
        }
    }

    //ui.listWidget->addItem(allProcess.name);
}

processenjoyer::~processenjoyer()
{

}
