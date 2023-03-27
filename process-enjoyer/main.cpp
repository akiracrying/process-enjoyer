#include "processenjoyer.h"
#include <QtWidgets/QApplication>

#include "backend.h" // added

int main(int argc, char *argv[]){
    // Egor loh

    QApplication a(argc, argv);
    processenjoyer w;
    w.show();
    return a.exec();

    // part that need to fill the processes struct //

    setlocale(LC_ALL, "");

    DWORD sePrivilege = SE_PRIVILEGE_ENABLED;
    turnDebugPrivilege(sePrivilege);

    processesDatabase();

    sePrivilege = 0;
    turnDebugPrivilege(sePrivilege);

    system("pause");
    return 0;
}
