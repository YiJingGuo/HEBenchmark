#include "hamminghelib.h"
#include "ui_hamminghelib.h"
#include "mainwindow.h"

#include <chrono>
#include <iostream>
#include <helib/FHE.h>
#include <helib/EncryptedArray.h>

using namespace std;
using namespace NTL;

HammingHElib::HammingHElib(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::HammingHElib)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
}

HammingHElib::~HammingHElib()
{
    delete ui;
}

void HammingHElib::ShowTxtToWindow()//显示文本文件中的内容
{
    QString fileName = "HammingHElibResult.txt";

    if(!fileName.isEmpty())
    {
        QFile *file = new QFile;
        file->setFileName(fileName);
        bool ok = file->open(QIODevice::ReadOnly);
        if(ok)
        {
            QTextStream in(file);
            ui->result->setText(in.readAll());
            file->close();
            delete file;
        }
        else
        {
            QMessageBox::information(this,"错误信息","打开文件:" + file->errorString());
            return;
        }
    }
}

void HammingHElib::StartTest()
{
    freopen("HammingHElibResult.txt","w",stdout);

    FHEcontext context(m, p, r);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::high_resolution_clock::time_point time_hamming_start, time_hamming_end;

    buildModChain(context, bits, c);

    std::cout << "Security: " << context.securityLevel() << std::endl;
    FHESecKey secret_key(context);
    cout << "Generating secretkeys : \n";
    time_start = chrono::high_resolution_clock::now();
    secret_key.GenSecKey();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    cout << "addSome1DMatrices : \n";
    time_start = chrono::high_resolution_clock::now();
    addSome1DMatrices(secret_key);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    cout << "Generating publickeys : \n";
    time_start = chrono::high_resolution_clock::now();
    const FHEPubKey& public_key = secret_key;
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    const EncryptedArray& ea  = *(context.ea);

    long nslots = ea.size();
    std::vector<long> ptxt1(nslots);
    std::vector<long> ptxt2(nslots);
    for (int i=0;i<nslots;++i) {
        ptxt1[i]=1;
        ptxt2[i]=0;
    }
    int temp = log2 (nslots);
    Ctxt ctxt1(public_key);
    Ctxt ctxt2(public_key);

    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_sub_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_totalSums_sum(0);
    chrono::microseconds time_plain_sum(0);

    vector<long> decrypted;
    for(int i=0;i<test_number;++i){

        time_hamming_start = chrono::high_resolution_clock::now();

        time_start = chrono::high_resolution_clock::now();
        ea.encrypt(ctxt1, public_key, ptxt1);
        ea.encrypt(ctxt2, public_key, ptxt2);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start)/2;
        noise_budget_initial = ctxt1.naturalSize();

        time_start = chrono::high_resolution_clock::now();
        ctxt1 -= ctxt2;
        time_end = chrono::high_resolution_clock::now();
        time_sub_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);


        time_start = chrono::high_resolution_clock::now();
        ctxt1.square ();
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);


        time_start = chrono::high_resolution_clock::now();
        ctxt1.reLinearize ();
        time_end = chrono::high_resolution_clock::now();
        time_relinearize_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

        time_start = chrono::high_resolution_clock::now();
        totalSums(ea,ctxt1);
        time_end = chrono::high_resolution_clock::now();
        time_totalSums_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

        time_hamming_end = chrono::high_resolution_clock::now();

        hamming_time.push_back(chrono::duration_cast<
                               chrono::microseconds>(time_hamming_end - time_hamming_start));
        noise_budget_end = ctxt1.naturalSize();
        /*
        [Decryption]
        */
        time_start = chrono::high_resolution_clock::now();
        ea.decrypt(ctxt1, secret_key, decrypted);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        /*********************测试明文hamming效率********************/
        vector<double> vec1;
        for (size_t i = 0; i < nslots; i++)
        {
            vec1.push_back(1 /* static_cast<double>(i)*/);
        }
        vector<double> vec2;
        for (size_t i = 0; i < nslots; i++)
        {
            vec2.push_back(0.0);
        }
        time_start = chrono::high_resolution_clock::now();
        //vec1 = vec1-vec2;
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
        //vec1 = vec1*vec1;
        transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
        for (int i=0;i<nslots;++i) {
            vector<double> temp;
            //旋转
            rotate_copy(vec1.begin (),vec1.begin ()+(1<<i),vec1.end (),back_inserter (temp));
            //date 1 = date 1+ temp
            transform(vec1.begin(), vec1.end(), temp.begin(),vec1.begin (), plus<double>());
        }
        time_end = chrono::high_resolution_clock::now();
        plain_time.push_back(chrono::duration_cast<
                             chrono::microseconds>(time_end - time_start));

        time_plain_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
    }
    std::cout << "Decrypted Ptxt: " << decrypted << std::endl;
    auto avg_encrypt = time_encrypt_sum.count() / test_number;
    auto avg_sub = time_sub_sum.count() / test_number;
    auto avg_square = time_square_sum.count() / test_number;
    auto avg_relinearize = time_relinearize_sum.count() / test_number;

    auto avg_totalSums = time_totalSums_sum.count() / test_number;
    auto avg_decrypt = time_decrypt_sum.count() / test_number;

    auto avg_hamming = avg_sub+avg_square+avg_relinearize+avg_totalSums;
    auto avg_time_plain_sum = time_plain_sum.count() / test_number;

    cout << "Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout << "The residual noise: "<<noise_budget_end<<" bits"<<endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average sub: " << avg_sub << " microseconds" << endl;
    cout << "Average square: " << avg_square << " microseconds" << endl;
    cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
    cout << "Average totalSums: " << avg_totalSums << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average hamming:" << avg_hamming << " microseconds" << endl;
    cout << "Average plain time:" << avg_time_plain_sum << " microseconds" << endl;
    cout << "执行总时间(不报括钥匙生成):"<<avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_totalSums+avg_decrypt<<" microseconds"<<endl;
    ShowTxtToWindow();
    charts();
}

void HammingHElib::on_pushButton_clicked()
{
    StartTest();
}

void HammingHElib::on_pushButton_2_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}


void HammingHElib::charts()
{
    QLineSeries *series = new QLineSeries();

    *series << QPointF(1, noise_budget_initial) << QPointF(2, noise_budget_end);

    QChart *chart = new QChart();
    chart->legend()->hide();
    chart->addSeries(series);
    //chart->createDefaultAxes();  //自动化建立XY轴

    QValueAxis *axisX = new QValueAxis();//轴变量、数据系列变量，都不能声明为局部临时变量
    QValueAxis *axisY = new QValueAxis();//创建X/Y轴
    axisX->setRange(1, 2);
    axisY->setRange(noise_budget_end-5, noise_budget_initial+5);//设置X/Y显示的区间
    chart->setAxisX(axisX);
    chart->setAxisY(axisY);//设置chart的坐标轴
    series->attachAxis(axisX);//连接数据集与坐标轴。
    series->attachAxis(axisY);

    chart->setTitle("噪音剩余空间");
    ui->graphicsView->setChart(chart);
    ui->graphicsView->setRenderHint(QPainter::Antialiasing);
}
