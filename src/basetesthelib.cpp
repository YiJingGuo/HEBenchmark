#include "basetesthelib.h"
#include "ui_basetesthelib.h"
#include "mainwindow.h"

BaseTestHElib::BaseTestHElib(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BaseTestHElib)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
}

BaseTestHElib::~BaseTestHElib()
{
    delete ui;
}


void BaseTestHElib::charts()
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

void BaseTestHElib::ShowTxtToWindow()//显示文本文件中的内容
{
    QString fileName = "result.txt";

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

void BaseTestHElib::test_add()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_add_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    for(int i=0;i<test_number;++i){
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt.addCtxt(ctxt);
        time_end = chrono::high_resolution_clock::now();
        time_add_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }

    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;


    auto avg_add = time_add_sum.count() / test_number;

    cout<<"Average add: "<<avg_add<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_add_plain()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_add_plain_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    ZZ plain;
    for(int i=0;i<test_number;++i){
        if(i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt.addConstant(plain);
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }

    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;


    auto avg_add_plain = time_add_plain_sum.count() / test_number;

    cout<<"Average add plain: "<<avg_add_plain<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_mult()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_mult_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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


    //计算生成密钥交换矩阵的时间
    if(KeySwitch == true)
    {
        cout<<"addSome1DMatrices : "<<endl;
        time_start = chrono::high_resolution_clock::now();
        addSome1DMatrices(*secKey);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    for(int i=0;i<test_number;++i){
        if(i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt *= ctxt;
        time_end = chrono::high_resolution_clock::now();
        time_mult_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }

    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_mult = time_mult_sum.count() / test_number;

    cout<<"Average multiply: "<<avg_mult<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_mult_plain()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_mult_plain_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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

    //计算生成密钥交换矩阵的时间
    if(KeySwitch == true)
    {
        cout<<"addSome1DMatrices : "<<endl;
        time_start = chrono::high_resolution_clock::now();
        addSome1DMatrices(*secKey);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    ZZ plain;
    for(int i=0;i<test_number;++i){
        if(i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt.multByConstant(plain);
        time_end = chrono::high_resolution_clock::now();
        time_mult_plain_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }

    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_mult_plain = time_mult_plain_sum.count() / test_number;

    cout<<"Average multiply plain: "<<avg_mult_plain<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_square()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_square_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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

    //计算生成密钥交换矩阵的时间
    if(KeySwitch == true)
    {
        cout<<"addSome1DMatrices : "<<endl;
        time_start = chrono::high_resolution_clock::now();
        addSome1DMatrices(*secKey);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    for(int i=0;i<test_number;++i){
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt.square();
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }

    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_square = time_square_sum.count() / test_number;

    cout<<"Average square: "<<avg_square<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_negation()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_negation_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    for(int i=0;i<test_number;++i){
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt.negate();
        time_end = chrono::high_resolution_clock::now();
        time_negation_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }
    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_negation = time_negation_sum.count() / test_number;

    cout<<"Average negate: "<<avg_negation<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_sub()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_sub_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    for(int i=0;i<test_number;++i){
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt -= ctxt;
        time_end = chrono::high_resolution_clock::now();
        time_sub_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }
    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_sub = time_sub_sum.count() / test_number;

    cout<<"Average sub: "<<avg_sub<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_xor()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_xor_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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

    //计算生成密钥交换矩阵的时间
    if(KeySwitch == true)
    {
        cout<<"addSome1DMatrices : "<<endl;
        time_start = chrono::high_resolution_clock::now();
        addSome1DMatrices(*secKey);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    ZZX plain;
    for(int i=0;i<test_number;++i){
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt.xorConstant(plain);
        time_end = chrono::high_resolution_clock::now();
        time_xor_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }
    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_xor = time_xor_sum.count() / test_number;

    cout<<"Average xor: "<<avg_xor<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_nxor()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_nxor_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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

    //计算生成密钥交换矩阵的时间
    if(KeySwitch == true)
    {
        cout<<"addSome1DMatrices : "<<endl;
        time_start = chrono::high_resolution_clock::now();
        addSome1DMatrices(*secKey);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    ZZX plain;
    for(int i=0;i<test_number;++i){
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_start = chrono::high_resolution_clock::now();
        ctxt.nxorConstant(plain);
        time_end = chrono::high_resolution_clock::now();
        time_nxor_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }
    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_nxor = time_nxor_sum.count() / test_number;

    cout<<"Average nxor: "<<avg_nxor<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_rotate_random()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_rotate_random_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    ZZX plain;
    for(int i=0;i<test_number;++i){
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        random_device rd;
        int random_rotation = static_cast<int>(rd() % nslots);
        time_start = chrono::high_resolution_clock::now();
        ctxt.operator>>=(random_rotation);
        time_end = chrono::high_resolution_clock::now();
        time_rotate_random_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
    }
    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_rotate_random = time_rotate_random_sum.count() / test_number;

    cout<<"Average Rotate Random: "<<avg_rotate_random<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_encryption()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_encryption_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }

    for(int i=0;i<test_number;++i){
        time_start = chrono::high_resolution_clock::now();
        Ctxt ctxt(*pubKey);
        ea.encrypt(ctxt, *pubKey, ptxt);
        if (i == 0)
        noise_budget_initial = ctxt.naturalSize();
        time_end = chrono::high_resolution_clock::now();
        time_encryption_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
        if(i == 0)
        noise_budget_end = ctxt.naturalSize();
        if(i == 0)
        {
        //密文保存本地
        ofstream of ("ctxt",std::ios::binary);
        ctxt.write (of);
        of.close();
        }
    }

    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_encryption = time_encryption_sum.count() / test_number;

    cout<<"Average encryption: "<<avg_encryption<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::test_decryption()
{
    ui->graphicsView->show();
    freopen("result.txt","w",stdout);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_decryption_sum(0);

    ofstream binFile("helib_publicKey",std::ios::binary);
    ofstream binFile2("helib_secKey",std::ios::binary);

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
    for (int i = 0; i < nslots; ++i) {
      ptxt[i] = i;
    }


    Ctxt ctxt(*pubKey);
    ea.encrypt(ctxt, *pubKey, ptxt);
    noise_budget_initial = ctxt.naturalSize();
    noise_budget_end = ctxt.naturalSize();
    //密文保存本地
    ofstream of ("ctxt",std::ios::binary);
    ctxt.write (of);
    of.close();

    std::vector<long> decrypted(nslots);

    for(int i=0;i<test_number;++i){
        time_start = chrono::high_resolution_clock::now();
        ea.decrypt(ctxt, *secKey, decrypted);
        time_end = chrono::high_resolution_clock::now();
        time_decryption_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
    }

    cout<<"Initial noise budget: "<<noise_budget_initial<<" bits"<<endl;
    cout<<"The residual noise: "<<noise_budget_end<<" bits"<<endl;

    auto avg_decryption = time_decryption_sum.count() / test_number;

    cout<<"Average decryption: "<<avg_decryption<< " microseconds"<<endl;

    //输出密文大小
    cout<<"密文大小:";
    ifstream fin("ctxt");
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
    ifstream finP("helib_publicKey");
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
    ifstream finS("helib_secKey");
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
}

void BaseTestHElib::on_start_clicked()
{
    if(test_type == "Add测试")
        test_add();
    if(test_type == "Add Plain测试")
        test_add_plain();
    if(test_type == "Mult测试")
        test_mult();
    if(test_type == "Mult Plain测试")
        test_mult_plain();
    if(test_type == "Square测试")
        test_square();
    if(test_type == "Negation测试")
        test_negation();
    if(test_type == "Sub测试")
        test_sub();
    if(test_type == "Xor测试")
        test_xor();
    if(test_type == "nXor测试")
        test_nxor();
    if(test_type == "Rotate Random测试")
        test_rotate_random();
    if(test_type == "Encryption测试")
        test_encryption();
    if(test_type == "Decryption测试")
        test_decryption();
}

void BaseTestHElib::on_lineEdit_textChanged(const QString &arg1)
{
    ui->lineEdit->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    test_number = arg1.toInt();
}

void BaseTestHElib::on_return_2_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}

void BaseTestHElib::on_TestType_activated(const QString &arg1)
{
    test_type = arg1;
}

void BaseTestHElib::on_radioButton_clicked(bool checked)
{
    KeySwitch = checked;
}
