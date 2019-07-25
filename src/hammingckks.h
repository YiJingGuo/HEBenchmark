#ifndef HAMMINGCKKS_H
#define HAMMINGCKKS_H

#include <QWidget>
#include <QMainWindow>
#include <QFile>
#include <QTextStream>
#include <QTimer>
#include "seal/seal.h"
#include <QtCharts>
#include <algorithm>

using namespace QtCharts;
using namespace std;
using namespace seal;

namespace Ui {
class HammingCkks;
}

class HammingCkks : public QWidget
{
    Q_OBJECT

public:
    explicit HammingCkks(QWidget *parent = nullptr);
    ~HammingCkks();
    int poly_modulus_degree = 1024;
    int coeff_modulus = 8192;
    int security_parameters = 128;
    int dbc = 30;
    int test_number = 10;

    double noise_budget_initial = 100;
    double noise_budget_end = 0;

    std::vector<chrono::microseconds> hamming_time;
    std::vector<chrono::microseconds> plain_time;

    void HammingCkks128(int poly_modulus_degree, int coeff_modulus, int dbc);
    void HammingCkks192(int poly_modulus_degree, int coeff_modulus, int dbc);
    void HammingCkks256(int poly_modulus_degree, int coeff_modulus, int dbc);
    void print_parameters(shared_ptr<SEALContext> context);
    void charts();

private slots:
    void on_security_level_activated(const QString &arg1);

    void on_poly_modulus_degree_activated(const QString &arg1);

    void on_coeff_modulus_activated(const QString &arg1);

    void on_dbc_activated(const QString &arg1);

    void on_test_times_textChanged(const QString &arg1);

    void on_start_clicked();

    void on_return_2_clicked();

private:
    Ui::HammingCkks *ui;
};

#endif // HAMMINGCKKS_H
