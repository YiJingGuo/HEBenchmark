#ifndef HAMMINGHELIB_H
#define HAMMINGHELIB_H

#include <QWidget>

namespace Ui {
class HammingHElib;
}

class HammingHElib : public QWidget
{
    Q_OBJECT

public:
    explicit HammingHElib(QWidget *parent = nullptr);
    ~HammingHElib();

    void StartTest();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::HammingHElib *ui;
};

#endif // HAMMINGHELIB_H
