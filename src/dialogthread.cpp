#include "dialog.h"
#include "ui_dialog.h"
#include "dialogthread.h"

DialogThread::DialogThread()
{
    isStop = false;
}

void DialogThread::closeThread()
{
    isStop = true;
}

void DialogThread::run()
{
    Dialog::show();
}
