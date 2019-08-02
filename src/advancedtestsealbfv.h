#ifndef ADVANCEDTESTSEALBFV_H
#define ADVANCEDTESTSEALBFV_H

#include <QWidget>
#include <QChartView>
#include <QtCharts>
#include <algorithm>
#include <vector>
#include "seal/seal.h"
#include<cmath>
using namespace std;
using namespace seal;
using namespace QtCharts;

namespace Ui {
class AdvancedTestSealBFV;
}

class AdvancedTestSealBFV : public QWidget
{
    Q_OBJECT

public:
    explicit AdvancedTestSealBFV(QWidget *parent = nullptr);
    ~AdvancedTestSealBFV();

    int poly_modulus_degree = 1024;
    int coeff_modulus = 4096;
    int security_parameters = 128;
    int plain_modulus = 786433;
    int test_number = 10;
    int noise_budget_initial = 80;
    int noise_budget_end = 78;
    int plain_size_max = 20;
    bool YesOrNoBatch = false;

    QString test_type = "Add测试";

    void print_parameters(shared_ptr<SEALContext> context);
    void AdvancedBFV128(int poly_modulus_degree, int coeff_modulus, int plain_modulus);
    void AdvancedBFV192(int poly_modulus_degree, int coeff_modulus, int plain_modulus);
    void AdvancedBFV256(int poly_modulus_degree, int coeff_modulus, int plain_modulus);
    void charts();
    void charts_contrast();
    void ShowTxtToWindowPlain();
    void ShowTxtToWindowPlainEnd();
    void test_add(shared_ptr<SEALContext> context);
    void test_add_plain(shared_ptr<SEALContext> context);
    void test_mult(shared_ptr<SEALContext> context);
    void test_mult_plain(shared_ptr<SEALContext> context);
    void test_sub(shared_ptr<SEALContext> context);
    void test_sub_plain(shared_ptr<SEALContext> context);
    void test_square(shared_ptr<SEALContext> context);
    void test_negation(shared_ptr<SEALContext> context);
    void test_rotate_rows_one_step(shared_ptr<SEALContext> context);
    void test_rotate_rows_random(shared_ptr<SEALContext> context);
    void test_rotate_columns(shared_ptr<SEALContext> context);

    std::vector<chrono::microseconds> cipher_time;
    std::vector<chrono::microseconds> plain_time;

private slots:
    void on_return_2_clicked();

    void on_security_level_activated(const QString &arg1);

    void on_poly_modulus_degree_activated(const QString &arg1);

    void on_coeff_modulus_activated(const QString &arg1);

    void on_plain_modulus_activated(const QString &arg1);

    void on_test_type_activated(const QString &arg1);

    void on_lineEdit_textChanged(const QString &arg1);

    void on_start_clicked();

    void on_radioButton_clicked(bool checked);

    void on_plain_size_textChanged(const QString &arg1);

private:
    Ui::AdvancedTestSealBFV *ui;
};

#endif // ADVANCEDTESTSEALBFV_H
