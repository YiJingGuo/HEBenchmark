#ifndef DIALOG_TESTING_H
#define DIALOG_TESTING_H

#include <QWidget>

namespace Ui {
class dialog_testing;
}

class dialog_testing : public QWidget
{
    Q_OBJECT

public:
    explicit dialog_testing(QWidget *parent = nullptr);
    ~dialog_testing();

private:
    Ui::dialog_testing *ui;
};

#endif // DIALOG_TESTING_H
