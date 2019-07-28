#include "dialog_testing.h"
#include "ui_dialog_testing.h"

dialog_testing::dialog_testing(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::dialog_testing)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
    ui->progressBar->setMinimum(0);
    ui->progressBar->setMaximum(0);
    ui->progressBar->setVisible(true);
}

dialog_testing::~dialog_testing()
{
    delete ui;
}
