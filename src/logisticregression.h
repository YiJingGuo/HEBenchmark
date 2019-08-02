#ifndef LOGISTICREGRESSION_H
#define LOGISTICREGRESSION_H

#include <QWidget>

namespace Ui {
class LogisticRegression;
}

class LogisticRegression : public QWidget
{
    Q_OBJECT

public:
    explicit LogisticRegression(QWidget *parent = nullptr);
    ~LogisticRegression();

    void testLR();
    void testHELR();
    char* filename = new char[1024];

    void ShowTxtToWindow();

    void ShowTxtToWindowCip();

    int polydeg = 3;

private slots:
    void on_pushButton_2_clicked();

    void on_return_2_clicked();

    void on_file_clicked();

    void on_comboBox_activated(const QString &arg1);

    void on_pushButton_clicked();

private:
    Ui::LogisticRegression *ui;
};

#endif // LOGISTICREGRESSION_H
