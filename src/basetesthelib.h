#ifndef BASETESTHELIB_H
#define BASETESTHELIB_H

#include <QWidget>
#include "parametergenerator.h"
#include "ui_parametergenerator.h"
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
class BaseTestHElib;
}

class BaseTestHElib : public QWidget
{
    Q_OBJECT

public:
    explicit BaseTestHElib(QWidget *parent = nullptr);
    ~BaseTestHElib();
    // Plaintext prime modulus
    unsigned long p = 2063;
    // Cyclotomic polynomial - defines phi(m)
    unsigned long m = 27026;
    // Hensel lifting (default = 1)
    unsigned long r = 1;
    // Number of bits of the modulus chain
    unsigned long bits = 300;
    // Number of columns of Key-Switching matix (default = 2 or 3)
    unsigned long c = 2;

    int test_number = 1;
    QString test_type = "Add测试";

    double noise_budget_initial = 222;
    double noise_budget_end = 221;
    void test_add();
    void test_add_plain();
    void test_mult();
    void test_mult_plain();
    void test_square();
    void test_negation();
    void test_sub();
    void test_xor();
    void test_nxor();
    void test_rotate_random();
    void test_encryption();
    void test_decryption();

    void charts();


    bool KeySwitch = false;

private slots:


    void on_start_clicked();

    void on_lineEdit_textChanged(const QString &arg1);

    void on_return_2_clicked();

    void on_TestType_activated(const QString &arg1);

    void on_radioButton_clicked(bool checked);
    void ShowTxtToWindow();

private:
    Ui::BaseTestHElib *ui;
};

#endif // BASETESTHELIB_H
