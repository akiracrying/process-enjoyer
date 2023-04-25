#include "processenjoyer.h"
#include <QtWidgets/QApplication>
#include <QtCore5Compat/QTextCodec>
#include "backend.h" // added


int main(int argc, char *argv[]){
    // Egor loh
    QApplication a(argc, argv);

    setlocale(LC_ALL, "Russian");
    QTextCodec::setCodecForLocale(QTextCodec::codecForName("UTF-8"));
  /*  QTextCodec* russian = QTextCodec::codecForName("CP1251");
    QTextCodec::setCodecForLocale(russian);*/
    processenjoyer w;
    w.show();
    return a.exec();
}
