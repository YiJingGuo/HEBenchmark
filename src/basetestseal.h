#ifndef BASETESTSEAL_H
#define BASETESTSEAL_H

#include <QMainWindow>
#include <QFile>
#include <QTextStream>
#include <QTimer>
#include "seal/seal.h"

using namespace std;
using namespace seal;

namespace Ui {
class BaseTestSeal;
}

class BaseTestSeal : public QMainWindow
{
    Q_OBJECT

public:
    explicit BaseTestSeal(QWidget *parent = nullptr);
    ~BaseTestSeal();
    int poly_modulus_degree = 1024;
    int coeff_modulus = 4096;
    int security_parameters = 128;
    int dbc = 30;
    int test_number = 200;
    QString test_type = "Add测试";
    void charts_contrast();
    std::vector<chrono::microseconds> cipher_time;
    std::vector<chrono::microseconds> plain_time;
    std::vector<chrono::microseconds> run_time;
    void charts_time();


private slots:

    void BaseCkks128(int poly_modulus_degree, int coeff_modulus, int dbc);
    void BaseCkks192(int poly_modulus_degree, int coeff_modulus, int dbc);
    void BaseCkks256(int poly_modulus_degree, int coeff_modulus, int dbc);


    void on_pushButton_clicked();

    void on_comboBox_activated(const QString &arg1);
    void on_comboBox_2_activated(const QString &arg1);
    void on_comboBox_3_activated(const QString &arg1);
    void on_comboBox_4_activated(const QString &arg1);
    void on_lineEdit_textChanged(const QString &arg1);
    void on_pushButton_2_clicked();
    void print_parameters(shared_ptr<SEALContext> context);


    void test_add(shared_ptr<SEALContext> context, int dbc);
    void test_add_plain(shared_ptr<SEALContext> context, int dbc);
    void test_mult(shared_ptr<SEALContext> context, int dbc);
    void test_mult_plain(shared_ptr<SEALContext> context, int dbc);
    void test_sub(shared_ptr<SEALContext> context, int dbc);
    void test_sub_plain(shared_ptr<SEALContext> context, int dbc);
    void test_square(shared_ptr<SEALContext> context, int dbc);
    void test_negation(shared_ptr<SEALContext> context, int dbc);
    void test_rotate_vector(shared_ptr<SEALContext> context, int dbc);
    void test_rotate_vector_random(shared_ptr<SEALContext> context, int dbc);
    void test_relinearize(shared_ptr<SEALContext> context, int dbc);
    void test_rescale(shared_ptr<SEALContext> context, int dbc);
    void test_encryption(shared_ptr<SEALContext> context, int dbc);
    void test_decryption(shared_ptr<SEALContext> context, int dbc);
    void test_encoding(shared_ptr<SEALContext> context, int dbc);
    void test_decoding(shared_ptr<SEALContext> context, int dbc);

    void on_TestType_activated(const QString &arg1);


private:
    Ui::BaseTestSeal *ui;
};

#endif // BASETESTSEAL_H
