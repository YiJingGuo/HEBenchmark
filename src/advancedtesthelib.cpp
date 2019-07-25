#include "advancedtesthelib.h"
#include "ui_advancedtesthelib.h"
#include "mainwindow.h"

AdvancedTestHElib::AdvancedTestHElib(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AdvancedTestHElib)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
    ui->testing->hide();
}

AdvancedTestHElib::~AdvancedTestHElib()
{
    delete ui;
}

void AdvancedTestHElib::charts()
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

    chart->setTitle("噪音消耗量");
    ui->graphicsView->setChart(chart);
    ui->graphicsView->setRenderHint(QPainter::Antialiasing);
}

void AdvancedTestHElib::charts_contrast()
{
    //密文坐标点导入
    QLineSeries *series = new QLineSeries();

    for(int i = 0;i<test_number;i++)
    *series << QPointF(i+1, cipher_time[i].count());

    //明文坐标点导入
    QLineSeries *series2 = new QLineSeries();
    for(int i = 0;i<test_number;i++)
    *series2 << QPointF(i+1, plain_time[i].count());

    QChart *chart = new QChart();
    chart->legend()->hide();
    chart->addSeries(series);
    chart->addSeries(series2);

    sort(cipher_time.begin(), cipher_time.end());
    sort(plain_time.begin(),plain_time.end());

    auto Ymax = (cipher_time.back().count())*1.2;
    auto Ymin = plain_time[0].count();
    if(plain_time.back().count() > (cipher_time.back().count())*1.2){
        Ymax = (plain_time.back().count())*1.2;
        Ymin = cipher_time[0].count();
    }

    QValueAxis *axisX = new QValueAxis();//轴变量、数据系列变量，都不能声明为局部临时变量
    QValueAxis *axisY = new QValueAxis();//创建X/Y轴
    axisX->setRange(1, test_number);
    axisY->setRange(Ymin, Ymax);//设置X/Y显示的区间
    chart->setAxisX(axisX);
    chart->setAxisY(axisY);//设置chart的坐标轴
    series->attachAxis(axisX);//连接数据集与坐标轴。
    series->attachAxis(axisY);

    //明文折线图
    chart->setAxisX(axisX,series2);
    chart->setAxisY(axisY,series2);

    chart->setTitle("明文运算时间与密文运算时间对比");

    ui->graphicsView_2->setChart(chart);
    ui->graphicsView_2->setRenderHint(QPainter::Antialiasing);

    plain_time.clear();
    cipher_time.clear();

}

void AdvancedTestHElib::ShowTxtToWindowPlain()
{
    QString fileName = "adv_HElib_plain_begin.txt";

    if(!fileName.isEmpty())
    {
        QFile *file = new QFile;
        file->setFileName(fileName);
        bool ok = file->open(QIODevice::ReadOnly);
        if(ok)
        {
            QTextStream in(file);
            ui->plain->setText(in.readAll());
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

void AdvancedTestHElib::ShowTxtToWindowPlainEnd()
{
    QString fileName = "adv_HElib_plain_end.txt";

    if(!fileName.isEmpty())
    {
        QFile *file = new QFile;
        file->setFileName(fileName);
        bool ok = file->open(QIODevice::ReadOnly);
        if(ok)
        {
            QTextStream in(file);
            ui->plain_end->setText(in.readAll());
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

void AdvancedTestHElib::ShowTxtToWindow()
{
    QString fileName = "adv_HElib_result.txt";

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
void AdvancedTestHElib::on_test_number_textChanged(const QString &arg1)
{
    ui->test_number->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    test_number = arg1.toInt();
}

void AdvancedTestHElib::on_pri_textChanged(const QString &arg1)
{
    ui->pri->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    p = arg1.toInt();
}


void AdvancedTestHElib::on_SetM_textChanged(const QString &arg1)
{
    ui->SetM->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    m = arg1.toInt();
}


void AdvancedTestHElib::on_SetR_textChanged(const QString &arg1)
{
    ui->SetR->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    r = arg1.toInt();
}

void AdvancedTestHElib::on_plain_size_textChanged(const QString &arg1)
{
    ui->plain_size->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    plain_size_max = arg1.toInt();
}

void AdvancedTestHElib::on_SetBits_textChanged(const QString &arg1)
{
    ui->SetBits->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    bits = arg1.toInt();
}

void AdvancedTestHElib::on_SetC_textChanged(const QString &arg1)
{
    ui->SetC->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    c = arg1.toInt();
}



void AdvancedTestHElib::on_return_2_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}

void AdvancedTestHElib::on_TestType_activated(const QString &arg1)
{
    test_type = arg1;
}

void AdvancedTestHElib::test_add()
{


    freopen("adv_HElib_result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_add_plain_sum(0);

    long plain_size = 0;

    ofstream binFile("adv_helib_publicKey",std::ios::binary);
    ofstream binFile2("adv_helib_secKey",std::ios::binary);

    //计算创建环境所需要的时间
    cout<<"Initialising context object..."<<endl;
    time_start = chrono::high_resolution_clock::now();
    std::unique_ptr<FHEcontext> context(new FHEcontext(m, p, r));
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    //计算创建模链时间
    cout<<"Building modulus chain..."<<endl;

    time_start = chrono::high_resolution_clock::now();
    buildModChain(*context, bits, c);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    //计算安全等级
    cout<<"Security: "<<context->securityLevel()<<endl;

    //计算生成密钥的时间
    std::unique_ptr<FHESecKey> secKey(new FHESecKey(*context));
    cout<<"Generating secretkeys : "<<endl;
    time_start = chrono::high_resolution_clock::now();
    secKey->GenSecKey();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    //计算生成公钥时间
    cout<<"Generating publickeys : "<<endl;
    time_start = chrono::high_resolution_clock::now();
    FHEPubKey* pubKey = (FHEPubKey*) secKey.get();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    //密钥公钥写入本地
    writePubKeyBinary(binFile, *pubKey);
    binFile.close();
    writeSecKeyBinary(binFile2, *secKey);
    binFile2.close();

    const EncryptedArray& ea = *(context->ea);

    //打印槽数
    long nslots = ea.size();
    cout<<"Number of slots: "<<nslots<<endl;

    //给明文赋值
    std::vector<long> ptxt(nslots);

    random_device rd;
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = rd() % plain_size_max;
    }
    freopen("adv_HElib_plain_begin.txt","w",stdout);
    cout<<ptxt<<endl;
    ShowTxtToWindowPlain();
    fclose(stdout);


    freopen("adv_HElib_result.txt","a",stdout);
    Ctxt ctxt(*pubKey);

    if(YesOrNoTestDepth){
        ea.encrypt(ctxt, *pubKey, ptxt);

        //密文保存本地
        ofstream of ("adv_HElib_ctxt",std::ios::binary);
        ctxt.write (of);
        of.close();
        for(int i=0;i<test_number;++i){
            noise_budget_initial = ctxt.naturalSize();
            time_start = chrono::high_resolution_clock::now();
            ctxt.addCtxt(ctxt);
            time_end = chrono::high_resolution_clock::now();
            time_add_sum += chrono::duration_cast<
                    chrono::microseconds>(time_end - time_start);
            cipher_time.push_back(chrono::duration_cast<
                                  chrono::microseconds>(time_end - time_start));
            noise_budget_end = ctxt.naturalSize();

            std::vector<long> decrypted(nslots);

            ea.decrypt(ctxt, *secKey, decrypted);
            freopen("adv_HElib_plain_end.txt","w",stdout);
            std::cout << decrypted << std::endl;
            ShowTxtToWindowPlainEnd();
            fclose(stdout);

            freopen("adv_HElib_result.txt","a",stdout);


            //计算明文运算时间
            random_device rd;
            vector<double> vec1;
            for (size_t i = 0; i < nslots; i++)
            {
                vec1.push_back(rd() % plain_size_max);
            }
            vector<double> vec2;
            for (size_t i = 0; i < nslots; i++)
            {
                vec2.push_back(rd() % plain_size_max);
            }

            plain_size = vec1.size ();
            time_start = chrono::high_resolution_clock::now();
            transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), plus<double>());
            time_end = chrono::high_resolution_clock::now();
            time_add_plain_sum +=chrono::duration_cast<
                    chrono::microseconds>(time_end - time_start) ;
            plain_time.push_back(chrono::duration_cast<
                                  chrono::microseconds>(time_end - time_start));

        }
    }else {
        for(int i=0;i<test_number;++i){

            ea.encrypt(ctxt, *pubKey, ptxt);

            //密文保存本地
            ofstream of ("adv_HElib_ctxt",std::ios::binary);
            ctxt.write (of);
            of.close();

            if (i == 0)
            noise_budget_initial = ctxt.naturalSize();
            time_start = chrono::high_resolution_clock::now();
            ctxt.addCtxt(ctxt);
            time_end = chrono::high_resolution_clock::now();
            time_add_sum += chrono::duration_cast<
                    chrono::microseconds>(time_end - time_start);
            cipher_time.push_back(chrono::duration_cast<
                                  chrono::microseconds>(time_end - time_start));
            if(i == 0)
            noise_budget_end = ctxt.naturalSize();

            std::vector<long> decrypted(nslots);

            ea.decrypt(ctxt, *secKey, decrypted);
            freopen("adv_HElib_plain_end.txt","w",stdout);
            std::cout << decrypted << std::endl;
            ShowTxtToWindowPlainEnd();
            fclose(stdout);

            freopen("adv_HElib_result.txt","a",stdout);


            //计算明文运算时间
            random_device rd;
            vector<double> vec1;
            for (size_t i = 0; i < nslots; i++)
            {
                vec1.push_back(rd() % plain_size_max);
            }
            vector<double> vec2;
            for (size_t i = 0; i < nslots; i++)
            {
                vec2.push_back(rd() % plain_size_max);
            }

            plain_size = vec1.size ();
            time_start = chrono::high_resolution_clock::now();
            transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), plus<double>());
            time_end = chrono::high_resolution_clock::now();
            time_add_plain_sum +=chrono::duration_cast<
                    chrono::microseconds>(time_end - time_start) ;
            plain_time.push_back(chrono::duration_cast<
                                  chrono::microseconds>(time_end - time_start));

        }
    }



    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_add = time_add_sum.count() / test_number;
    auto avg_add_plain = time_add_plain_sum.count() / test_number;

    auto ratio  = avg_add/(double)avg_add_plain;

    cout<<"Average add: "<<avg_add<< " microseconds"<<endl;
    cout<<"Average plain-text addition time:"<<avg_add_plain<<" microseconds"<<endl;
    cout<<"密文运算与明文运算时间比: "<<ratio<<endl;
    cout<<"明文的大小:"<<plain_size<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("adv_HElib_ctxt");
    if( fin.is_open() )
    {
        fin.seekg( 0, ios::end );
        int size = fin.tellg();
        fin.close();
        cout<<size;
    }
    cout<<"Byte"<<endl;

    //输出公钥大小：
    cout<<"公钥大小:";
    ifstream finP("adv_helib_publicKey");
    if( finP.is_open() )
    {
        finP.seekg( 0, ios::end );
        int size = finP.tellg();
        finP.close();
        cout<<size;
    }
    cout<<"Byte"<<endl;

    //输出密钥大小：
    cout<<"密钥大小:";
    ifstream finS("adv_helib_secKey");
    if( finS.is_open() )
    {
        finS.seekg( 0, ios::end );
        int size = finS.tellg();
        finS.close();
        cout<<size;
    }
    cout<<"Byte"<<endl;

    ShowTxtToWindow();
    charts();
    charts_contrast();
}

void AdvancedTestHElib::on_start_clicked()
{
    if(test_type == "Add测试")
        test_add();
}

void AdvancedTestHElib::on_checkBox_clicked(bool checked)
{
    YesOrNoTestDepth = checked;
}

void AdvancedTestHElib::on_checkBox_2_clicked(bool checked)
{
    KeySwitch = checked;
}


void AdvancedTestHElib::on_pushButton_clicked()
{
    ParameterGenerator *win = new ParameterGenerator;
    win->show();
}
