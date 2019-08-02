#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "basetesthelib.h"
#include "ui_basetesthelib.h"
#include "basetestseal.h"
#include "basetestsealbfv.h"
#include "hammingckks.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

//    void mousePressEvent(QMouseEvent *e);


private slots:

    void on_pushButton_2_clicked();

    void on_pushButton_clicked();

    void on_pushButton_3_clicked();

    void on_pushButton_10_clicked();

    void on_pushButton_9_clicked();

    void on_pushButton_4_clicked();

    void on_pushButton_6_clicked();

    void on_pushButton_11_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
