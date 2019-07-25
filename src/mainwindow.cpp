#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "hamminghelib.h"
#include "advancedtestsealbfv.h"
#include "advancedtesthelib.h"
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_2_clicked()
{
    BaseTestSeal *win = new BaseTestSeal;
    win->show();
    this->hide();
}

void MainWindow::on_pushButton_clicked()
{
    BaseTestSealBFV *win = new BaseTestSealBFV;
    win->show();
    this->hide();
}

void MainWindow::on_pushButton_3_clicked()
{
    BaseTestHElib *win = new BaseTestHElib;
    win->show();
    this->hide();
}

void MainWindow::on_pushButton_10_clicked()
{
    HammingCkks *win = new HammingCkks;
    win->show();
    this->hide();
}

void MainWindow::on_pushButton_9_clicked()
{
    HammingHElib *win = new HammingHElib;
    win->show();
    this->hide();
}

void MainWindow::on_pushButton_4_clicked()
{
    AdvancedTestSealBFV *win = new AdvancedTestSealBFV;
    win->show();
    this->hide();
}

void MainWindow::on_pushButton_6_clicked()
{
    AdvancedTestHElib *win = new AdvancedTestHElib;
    win->show();
    this->hide();
}
