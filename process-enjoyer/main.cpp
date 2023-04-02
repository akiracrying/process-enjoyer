#include "processenjoyer.h"
#include <QtWidgets/QApplication>

#include "backend.h" // added

int main(int argc, char *argv[]){
    // Egor loh
    QApplication a(argc, argv);
    processenjoyer w;
    w.show();
    return a.exec();
}
