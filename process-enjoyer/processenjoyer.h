#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_processenjoyer.h"
#include <Windows.h>


class processenjoyer : public QMainWindow
{
    Q_OBJECT

public:
    processenjoyer(QWidget *parent = nullptr);
    ~processenjoyer();

private:
    HANDLE pipePtr;
    void setMandatoryLevel(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten);
    void setProcessIntegrity(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten);

    void getMandatoryLevel(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten);
    void getProcessIntegrity(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten);

    Ui::processenjoyerClass ui;
};
