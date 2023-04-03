#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_processenjoyer.h"

class processenjoyer : public QMainWindow
{
    Q_OBJECT

public:
    processenjoyer(QWidget *parent = nullptr);
    ~processenjoyer();

private:
    Ui::processenjoyerClass ui;
};
