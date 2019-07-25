#ifndef BASETESTSEALBFV_H
#define BASETESTSEALBFV_H

#include <QWidget>
#include <QChartView>
#include <QtCharts>
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace QtCharts;


namespace Ui {
class BaseTestSealBFV;
}

class BaseTestSealBFV : public QWidget
{
    Q_OBJECT

public:
    explicit BaseTestSealBFV(QWidget *parent = nullptr);
    ~BaseTestSealBFV();
    int poly_modulus_degree = 1024;
    int coeff_modulus = 4096;
    int security_parameters = 128;
    int plain_modulus = 786433;
    int test_number = 1;
    int noise_budget_initial = 80;
    int noise_budget_end = 78;
    QString test_type = "Add测试";



private slots:
    void print_parameters(shared_ptr<SEALContext> context);
    void BaseBFV128(int poly_modulus_degree, int coeff_modulus, int plain_modulus);
    void BaseBFV192(int poly_modulus_degree, int coeff_modulus, int plain_modulus);
    void BaseBFV256(int poly_modulus_degree, int coeff_modulus, int plain_modulus);

    void charts();

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
    void test_encryption(shared_ptr<SEALContext> context);
    void test_decryption(shared_ptr<SEALContext> context);
    void test_batching(shared_ptr<SEALContext> context);
    void test_unbatching(shared_ptr<SEALContext> context);

    void on_TestType_activated(const QString &arg1);

    void on_ToBeginTesting_clicked();

    void on_Return_clicked();

    void on_lineEdit_textChanged(const QString &arg1);

    void on_security_parameters_activated(const QString &arg1);

    void on_poly_modulus_degree_activated(const QString &arg1);

    void on_coeff_modulus_activated(const QString &arg1);

    void on_plain_modulus_activated(const QString &arg1);

private:
    Ui::BaseTestSealBFV *ui;
};

#endif // BASETESTSEALBFV_H
