#ifndef PARAMETERGENERATOR_H
#define PARAMETERGENERATOR_H

#include <QWidget>
#include <QMutex>
#include "basetesthelib.h"
#include "generatorthread.h"


namespace Ui {
class ParameterGenerator;
}

class ParameterGenerator : public QWidget
{
    Q_OBJECT

public:
    explicit ParameterGenerator(QWidget *parent = nullptr);
    ~ParameterGenerator();
    void ShowTxtToWindow();
    bool run = true;

private slots:
    void on_generate_clicked();

    void on_stop_clicked();

    void openThreadBtnSlot();
    void closeThreadBtnSlot();
    void on_lineEdit_p_textChanged(const QString &arg1);
    void on_lineEdit_m1_textChanged(const QString &arg1);

    void on_lineEdit_m2_textChanged(const QString &arg1);

    void on_lineEdit_k1_textChanged(const QString &arg1);

    void on_lineEdit_k2_textChanged(const QString &arg1);

    void on_lineEdit_s1_textChanged(const QString &arg1);

    void on_lineEdit_s2_textChanged(const QString &arg1);

    void on_update_clicked();

private:
    Ui::ParameterGenerator *ui;

    GeneratorThread *thread1;

};

#endif // PARAMETERGENERATOR_H
