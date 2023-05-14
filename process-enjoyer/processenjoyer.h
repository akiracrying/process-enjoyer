#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_processenjoyer.h"

enum error_codes {
    NO_FILE = 228,
    NOT_SELECTED = 1337,
};
class processenjoyer : public QMainWindow
{
    Q_OBJECT

public:
    processenjoyer(QWidget *parent = nullptr);
    ~processenjoyer();

private:
    void setMandatoryLevel(Ui::processenjoyerClass ui, void* hPipe, unsigned long dwWritten);
    Ui::processenjoyerClass ui;
};
