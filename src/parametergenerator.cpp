#include "parametergenerator.h"
#include "ui_parametergenerator.h"
#include <QThread>
#include "unitex.h"


ParameterGenerator::ParameterGenerator(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ParameterGenerator)
{
    ui->setupUi(this);
    thread1 = new GeneratorThread;
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);

}

ParameterGenerator::~ParameterGenerator()
{
    delete ui;
}

void ParameterGenerator::openThreadBtnSlot()
{
    /*开启一个线程*/
    thread1->start();
}

void ParameterGenerator::closeThreadBtnSlot()
{
    /*关闭多线程*/
    thread1->closeThread();
    thread1->wait();
}

void Delay_MSec_Suspend(unsigned int msec)
{
    QTime _Timer = QTime::currentTime().addMSecs(msec);
    while( QTime::currentTime() < _Timer );
}
void ParameterGenerator::on_generate_clicked()
{
    openThreadBtnSlot();

    Delay_MSec_Suspend(2000);
    ShowTxtToWindow();
}

void ParameterGenerator::on_stop_clicked()
{
    closeThreadBtnSlot();
    run = false;
}

void ParameterGenerator::ShowTxtToWindow()//显示文本文件中的内容
{
    QString fileName = "generator_parm.txt";

    if(!fileName.isEmpty())
    {
        QFile *file = new QFile;
        file->setFileName(fileName);
        bool ok = file->open(QIODevice::ReadOnly);
        if(ok)
        {
            QTextStream in(file);
            ui->result->setText(in.readAll());
            file->close();
            delete file;
        }
        else
        {
            QMessageBox::information(this,"错误信息","打开文件:" + file->errorString());
            return;
        }
    }
}

void ParameterGenerator::on_lineEdit_p_textChanged(const QString &arg1)
{
    QMutex mutex;
    mutex.lock();
    Unitex::pri = arg1.toInt();
    mutex.unlock();
}

void ParameterGenerator::on_lineEdit_m1_textChanged(const QString &arg1)
{
    QMutex mutex;
    mutex.lock();
    Unitex::m1 = arg1.toInt();
    mutex.unlock();
}

void ParameterGenerator::on_lineEdit_m2_textChanged(const QString &arg1)
{
    QMutex mutex;
    mutex.lock();
    Unitex::m2 = arg1.toInt();
    mutex.unlock();
}

void ParameterGenerator::on_lineEdit_k1_textChanged(const QString &arg1)
{
    QMutex mutex;
    mutex.lock();
    Unitex::k1 = arg1.toInt();
    mutex.unlock();
}

void ParameterGenerator::on_lineEdit_k2_textChanged(const QString &arg1)
{
    QMutex mutex;
    mutex.lock();
    Unitex::k2 = arg1.toInt();
    mutex.unlock();
}


void ParameterGenerator::on_lineEdit_s1_textChanged(const QString &arg1)
{
    QMutex mutex;
    mutex.lock();
    Unitex::s1 = arg1.toInt();
    mutex.unlock();
}

void ParameterGenerator::on_lineEdit_s2_textChanged(const QString &arg1)
{
    QMutex mutex;
    mutex.lock();
    Unitex::s2 = arg1.toInt();
    mutex.unlock();
}

void ParameterGenerator::on_update_clicked()
{
    ShowTxtToWindow();
}
