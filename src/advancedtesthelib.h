#ifndef ADVANCEDTESTHELIB_H
#define ADVANCEDTESTHELIB_H

#include <QWidget>
#include <chrono>
#include <iostream>
#include <helib/FHE.h>
#include <helib/EncryptedArray.h>
#include <QtCharts>
#include <QFile>
#include <QTextStream>
#include <QTimer>
using namespace QtCharts;
using namespace std;
using namespace NTL;

namespace Ui {
class AdvancedTestHElib;
}

class AdvancedTestHElib : public QWidget
{
    Q_OBJECT

public:
    explicit AdvancedTestHElib(QWidget *parent = nullptr);
    ~AdvancedTestHElib();

    // Plaintext prime modulus
    unsigned long p = 4999;
    // Cyclotomic polynomial - defines phi(m)
    unsigned long m = 32109;
    // Hensel lifting (default = 1)
    unsigned long r = 1;
    // Number of bits of the modulus chain
    unsigned long bits = 300;
    // Number of columns of Key-Switching matix (default = 2 or 3)
    unsigned long c = 2;

    int plain_size_max = 2;
    bool YesOrNoTestDepth = false;
    bool KeySwitch = false;
    int test_number = 3;
    double noise_budget_initial = 222;
    double noise_budget_end = 221;
    QString test_type = "Add测试";

    void charts();
    void charts_contrast();
    void ShowTxtToWindow();
    void ShowTxtToWindowPlain();
    void ShowTxtToWindowPlainEnd();

    std::vector<chrono::microseconds> cipher_time;
    std::vector<chrono::microseconds> plain_time;
    void test_add();


private slots:
    void on_test_number_textChanged(const QString &arg1);

    void on_pri_textChanged(const QString &arg1);

    void on_SetM_textChanged(const QString &arg1);

    void on_SetR_textChanged(const QString &arg1);

    void on_plain_size_textChanged(const QString &arg1);

    void on_SetBits_textChanged(const QString &arg1);

    void on_SetC_textChanged(const QString &arg1);

    void on_return_2_clicked();

    void on_TestType_activated(const QString &arg1);

    void on_start_clicked();

    void on_checkBox_clicked(bool checked);

    void on_checkBox_2_clicked(bool checked);


    void on_pushButton_clicked();

private:
    Ui::AdvancedTestHElib *ui;
};

#endif // ADVANCEDTESTHELIB_H
