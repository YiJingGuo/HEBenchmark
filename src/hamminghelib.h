#ifndef HAMMINGHELIB_H
#define HAMMINGHELIB_H

#include <QWidget>
using namespace std;

namespace Ui {
class HammingHElib;
}

class HammingHElib : public QWidget
{
    Q_OBJECT


public:
    explicit HammingHElib(QWidget *parent = nullptr);
    ~HammingHElib();
    void ShowTxtToWindow();

    // Plaintext prime modulus
    unsigned long p = 149;
    // Cyclotomic polynomial - defines phi(m)
    unsigned long m = 13751;
    // Hensel lifting (default = 1)
    unsigned long r = 1;
    // Number of bits of the modulus chain
    unsigned long bits = 300;
    // Number of columns of Key-Switching matix (default = 2 or 3)
    unsigned long c = 2;

    int test_number = 1;
    void charts();
    double noise_budget_initial = 222;
    double noise_budget_end = 221;

    std::vector<chrono::microseconds> hamming_time;
    std::vector<chrono::microseconds> plain_time;

private slots:
    void on_pushButton_clicked();
    void StartTest();
    void on_pushButton_2_clicked();

private:
    Ui::HammingHElib *ui;
};

#endif // HAMMINGHELIB_H
