#include "processenjoyer.h"
#include <QtWidgets/QApplication>
#include <QStringConverter>
#include "backend.h" // added

int main(int argc, char *argv[]){
    // Egor loh
    QApplication a(argc, argv);
    QIcon icon("C:\\Users\\Timon\\Desktop\\Folders\\Projects\\MBKS2\\process-enjoyer\\process-enjoyer\\icon.ico");
    a.setWindowIcon(icon);
    processenjoyer w;
    w.show();
    return a.exec();
}
