#include "logisticregression.h"
#include "ui_logisticregression.h"

#include <cmath>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <sys/time.h>
#include <chrono>
#include <sys/resource.h>   // check the memory usage
#include <stdio.h>
#include <thread>
#include <fstream>
#include <sstream>

#include <NTL/RR.h>
#include <NTL/xdouble.h>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/BasicThreadPool.h>


#include "HELR/CZZ.h"
#include "HELR/Params.h"
#include "HELR/PubKey.h"
#include "HELR/Scheme.h"
#include "HELR/SchemeAlgo.h"
#include "HELR/SecKey.h"
#include "HELR/TestScheme.h"
#include "HELR/TimeUtils.h"
#include "HELR/Ring2Utils.h"
#include "HELR/StringUtils.h"
#include "HELR/EvaluatorUtils.h"

#include "Database.h"
#include "LRtest.h"
#include "HELR.h"
#include <QFile>
#include <QtDebug>
#include <QFileDialog>
#include "mainwindow.h"
using namespace NTL;
using namespace std;

LogisticRegression::LogisticRegression(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::LogisticRegression)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
}

LogisticRegression::~LogisticRegression()
{
    delete ui;
}


void LogisticRegression::testHELR()
{
    /*
    if(Argc != 3){
        cout << "-------------------------------------------------------------" << endl;
        cerr << "Enter the File and degree of approximation \t"  << "(e.g. $test edin.txt 3) \n ";
    }
    */
    //qDebug()<< QDir::currentPath();
    //  char* filename  =  Argv[1];
    // int polydeg = atoi(Argv[2]);  // degree of approximation polynomial
//    char* filename = "data/edin.txt";

    /*QFile file(filename);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qDebug()<<file.errorString();
    }else{
        cout<<"errorrrr"<<endl;
    }*/
//    int polydeg = 3;
    dMat  zData;
    dMat* zTest = new dMat[5];
    dMat* zTrain = new dMat[5];

    freopen("mid_result.txt","w",stdout);
    int nLine= readData(zData, filename);

    cout << "Sample the learning and test data ..." << endl;
    cvRandomSamplingData(zTrain, zTest, zData, filename);


    //----------------------------------------------------------------
    // Parameters for Logistic regression
    //----------------------------------------------------------------

    long logN= 11;
    long logp= 28;
    long logl= 10;
    long logq, cBit1, cBit2;
    int max_iter;

    struct LRpar LRparams;
    ReadLRparams(LRparams, max_iter, zTrain[0], polydeg, logp);

    SetNumThreads(LRparams.dim1);
    //SetNumThreads(4);

    switch(polydeg){
    case 3:
        cBit1=  (LRparams.logn - LRparams.log2polyscale);          // 1st iteration
        cBit2 =  (3*logp+ LRparams. logn - LRparams.log2polyscale);  // 2nd~ iteration
        logq = cBit1 + (LRparams.max_iter-1)*(cBit2)+ logp + logl;                  // max-bitlength we need
        break;

    case 7:
        cBit1=  (LRparams.logn - LRparams.log2polyscale);          // 1st iteration
        cBit2=  (4*logp+ LRparams.logn - LRparams.log2polyscale);
        logq= cBit1 + (LRparams.max_iter-1)*(cBit2)+ logp + logl;
        break;
    }


    freopen("cipher training.txt","w",stdout);

    cout << "Data dimension with dummy vectors: " << LRparams.dim1 << ", Number of lines: " << nLine << endl;

    cout << "-------------------------------------------------------------" << endl;
    cout << "Key Generation ... (logN,logp,logq, nslots)= (" ;
    cout << logN << "," << logp << "," << logq << "," << LRparams.nslots << ")" <<endl;

    auto start= chrono::steady_clock::now();

    Params params(logN, logq);
    SecKey secretKey(params);
    PubKey publicKey(params, secretKey);
    SchemeAux schemeaux(logN);
    Scheme scheme(params, publicKey, schemeaux);
    SchemeAlgo algo(scheme);

    auto end = std::chrono::steady_clock::now();
    auto diff = end - start;
    cout << "KeyGen time= " << chrono::duration <double, milli> (diff).count()/1000.0 << " s" << endl;




    LogReg LR(scheme, secretKey, LRparams);
    dMat HEtheta_list;



    int count = 5;
    for(int k = 0; k < count; ++k){

        cout << "-------------------------------------------------------------" << endl;
        cout << k << "th Data Encryption ... " << endl;

        struct rusage usage;

        start= chrono::steady_clock::now();

        Cipher* zTrainCipher = new Cipher[LRparams.dim1];

        LR.EncryptData(zTrainCipher, zTrain[k]);

        end = std::chrono::steady_clock::now();
        diff = end - start;
        cout << "Enc time= "  << chrono::duration <double, milli> (diff).count()/1000.0 << "(s), " ;

        int ret = getrusage(RUSAGE_SELF,&usage);
        cout<< "Mem: " << usage.ru_maxrss/(1024)  << "(MB)" << endl;


        cout << "-------------------------------------------------------------" << endl;
        cout << "HE Logistic Regression ... "  << endl;

        Cipher* thetaCipher= new Cipher[LRparams.dim1];

        start= chrono::steady_clock::now();

        LR.HElogreg(thetaCipher, zTrainCipher, zTrain[k]);


        end = std::chrono::steady_clock::now();
        diff = end - start;
        cout << "Eval time= "  << chrono::duration <double, milli> (diff).count()/1000.0 << "(s), " ;

        ret = getrusage(RUSAGE_SELF,&usage);
        cout<< "Mem: " << usage.ru_maxrss/(1024)  << "(MB)" << endl;


        cout << "-------------------------------------------------------------" << endl;
        cout << "Decryption ... "  << endl;

        dVec HEtheta(LRparams.dim1, 0.0);

        CZZ* dtheta = new CZZ[LRparams.dim1];

        for(int i=0; i< LRparams.dim1; ++i){
            dtheta[i] = (scheme.decrypt(secretKey, thetaCipher[i]))[0];

            conv(HEtheta[i], dtheta[i].r);
            HEtheta[i] = scaledown(HEtheta[i], LRparams.logp);
            cout << "[" << HEtheta[i] << "] " ;
        }
        cout << ": enc " << endl;

        getAUC(HEtheta, zTest[k]);
        HEtheta_list.push_back(HEtheta);



        cout << "-------------------------------------------------------------" << endl;
        cout << "Compare with unenc LR " << endl;
        dVec mtheta(LRparams.dim1, 0.0);

        for(int i= 0; i< LRparams.max_iter; i++){
            LR_poly(mtheta, zTrain[k], LRparams);
        }

        for(int i= 0; i< LRparams.dim1; i++)
            cout << "[" << mtheta[i] << "] " ;
        cout << ": unenc " << endl;

        getAUC(mtheta, zTest[k]);

        cout << "MSE (HELR/non-HELR): " << getMSE(HEtheta, mtheta) << endl;


        cout << "-------------------------------------------------------------" << endl;
        cout << "Compare with sigmoid LR " << endl;
        dVec mtheta_sig(LRparams.dim1, 0.0);

        for(int i= 0; i< LRparams.max_iter; i++){
            LR_sigmoid(mtheta_sig, zTrain[k], LRparams);
        }

        for(int i= 0; i< LRparams.dim1; i++)
            cout << "[" << mtheta_sig[i] << "] " ;
        cout << ": unenc " << endl;

        getAUC(mtheta_sig, zTest[k]);

        cout << "MSE (HELR/non-HELR): " << getMSE(HEtheta, mtheta_sig) << endl;

    }
    ofstream fout;
    fout.open("beta_HELR.txt");
    //! write the beta results in the text file
    fout << "-------------------------------------------------------------" << endl;
    fout << "[" << endl;
    //        for(int i = 0; i < LRparams.dim1; ++i){
    //            for(int k = 0; k < count-1; ++k){
    //                fout << HEtheta_list[k][i] << "," ;
    //            }
    //            fout << HEtheta_list[count-1][i] << ";" << endl;
    //        }

    for (int k=0;k<count;k++) {
        for(int i = 0; i < LRparams.dim1-1; ++i){
            fout << HEtheta_list[k][i] << "," ;
        }
        fout << HEtheta_list[k][LRparams.dim1-1]<<";";
        fout<<"\n";
    }
//    for(int i = 0; i < LRparams.dim1; ++i){
//        for(int k = 0; k < count-1; ++k){
//            fout << HEtheta_list[k][i] << "," ;
//        }
//        fout << HEtheta_list[count-1][i] << ";" << endl;
//    }
    //    for(int i = 0; i < HEtheta_list.size(); ++i){
    //        for(int k = 0; k < HEtheta_list[0].size(); ++k){
    //            fout << HEtheta_list[i][k] << "," ;

    //        }
    //        //fout << HEtheta_list[i][i] << ";" << endl;
    //    }
    fout << "];" << endl;
    fout.close();


    delete[] zTest;
    delete[] zTrain;
    ShowTxtToWindowCip();

}

void LogisticRegression::testLR()
{
    /*if(Argc != 2){
        cout << "-------------------------------------------------------------" << endl;
        cerr << "Enter the File and degree of approximation \t"  << "(e.g. $test edin.txt 3) \n ";
    }
    cout<<"Argc:"<<Argc<<endl;*/
//    filename  =  "data/edin.txt";

    /*
    QFile file(filename);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qDebug()<<file.errorString();
    }else{
        cout<<"success"<<endl;
    }*/
    dMat  zData;
    dMat* zTest = new dMat[5];
    dMat* zTrain = new dMat[5];

    int nLine= readData(zData, filename);
    /*
    for(int i=0;i<zData.size();++i){
        for(int j=0;j<zData[0].size();++j){
            cout<<zData[i][j]<<" ";
        }
        cout<<endl;
    }*/

    freopen("plaintext training.txt","w",stdout);

    cout << "Sample the learning and test data ..." << endl;
    cvRandomSamplingData(zTrain, zTest, zData, filename);


    //----------------------------------------------------------------
    // Parameters for Logistic regression
    //----------------------------------------------------------------

    long logN= 11;
    long logp= 28;
    long logl= 10;
    long logq, cBit1, cBit2;
    int max_iter;
    long dim ;


    dMat mtheta3_list;
    dMat mtheta7_list;
    dMat mtheta_sig_list;

    ofstream fout;
    fout.open("beta_LR.txt");


    for(int k = 0; k < 5; ++k){


        cout << "-------------------------------------------------------------" << endl;
        cout << "HELR_3 " << endl;

        //int polydeg = 3;  // degree of approximation polynomial

        struct LRpar LRparams;
        ReadLRparams(LRparams, max_iter, zTrain[0], polydeg, logp);

        dVec mtheta3(LRparams.dim1, 0.0);
        for(int i= 0; i< LRparams.max_iter; i++){
            LR_poly(mtheta3, zTrain[k], LRparams);
        }

        for(int i= 0; i< LRparams.dim1; i++)
            cout << "[" << mtheta3[i] << "] " ;
        cout  << endl;

        getAUC(mtheta3, zTest[k]);
        mtheta3_list.push_back(mtheta3);


        cout << "-------------------------------------------------------------" << endl;
        cout << "HELR_7 " << endl;

        polydeg = 7;  // degree of approximation polynomial

        struct LRpar LRparams7;
        ReadLRparams(LRparams7, max_iter, zTrain[0], polydeg, logp);

        dVec mtheta7(LRparams7.dim1, 0.0);
        for(int i= 0; i< LRparams7.max_iter; i++){
            LR_poly(mtheta7, zTrain[k], LRparams7);
        }

        for(int i= 0; i< LRparams7.dim1; i++)
            cout << "[" << mtheta7[i] << "] " ;
        cout  << endl;

        getAUC(mtheta7, zTest[k]);
        mtheta7_list.push_back(mtheta7);

        dim = LRparams7.dim1;


        cout << "-------------------------------------------------------------" << endl;
        cout << "sigmoid LR " << endl;
        dVec mtheta_sig(LRparams.dim1, 0.0);

        for(int i= 0; i< LRparams.max_iter; i++){
            LR_sigmoid(mtheta_sig, zTrain[k], LRparams);
        }

        for(int i= 0; i< LRparams.dim1; i++)
            cout << "[" << mtheta_sig[i] << "] " ;
        cout  << endl;

        getAUC(mtheta_sig, zTest[k]);
        mtheta_sig_list.push_back(mtheta_sig);


        cout << "-------------------------------------------------------------" << endl;
        cout << "MSE (HELR/non-HELR): " << getMSE(mtheta3, mtheta_sig) << endl;
        cout << "MSE (HELR/non-HELR): " << getMSE(mtheta7, mtheta_sig) << endl;

    }


    //! write the beta results in the text file
    fout << "-------------------------------------------------------------" << endl;
    fout << "HELR_3" << endl<<"[\n";

    for (int k=0;k<5;k++) {
        for(int i = 0; i < dim-1; ++i){
            fout << mtheta3_list[k][i] << "," ;
        }
        fout << mtheta3_list[k][dim-1]<<";";
        fout<<"\n";
    }
    fout<<"]"<<endl;

    /*
    for(int i = 0; i < dim; ++i){
        for(int k = 0; k < 4; ++k){
            fout << mtheta3_list[k][i] << "," ;
        }
        fout << mtheta3_list[4][i] << ";" << endl;
    }
    fout<<"]"<<endl;
    */
    fout << "-------------------------------------------------------------" << endl;
    fout << "HELR_7" << endl<<"[";
    for (int k=0;k<5;k++) {
        for(int i = 0; i < dim-1; ++i){
            fout << mtheta7_list[k][i] << "," ;
        }
        fout << mtheta7_list[k][dim-1]<<";";
        fout<<"\n";
    }
    fout<<"]"<<endl;
//    for(int i = 0; i < dim; ++i){
//        for(int k = 0; k < 4; ++k){
//            fout << mtheta7_list[k][i] << "," ;
//        }
//        fout << mtheta7_list[4][i] << ";" << endl;
//    }
//    fout << "]" << endl;

    fout << "-------------------------------------------------------------" << endl;
    fout << "LR" << endl<<"[";
    for (int k=0;k<5;k++) {
        for(int i = 0; i < dim-1; ++i){
            fout << mtheta_sig_list[k][i] << "," ;
        }
        fout << mtheta_sig_list[k][dim-1]<<";";
        fout<<"\n";
    }
    fout << "]" << endl;
//    for(int i = 0; i < dim; ++i){
//        for(int k = 0; k < 4; ++k){
//            fout << mtheta_sig_list[k][i] << "," ;
//        }
//        fout << mtheta_sig_list[4][i] << ";" << endl;
//    }
//    fout<<"]"<<endl;
    fout.close();

    fout << "-------------------------------------------------------------" << endl;

    delete[] zTest;
    delete[] zTrain;

    ShowTxtToWindow();
}

void LogisticRegression::on_pushButton_2_clicked()
{
    testLR();
}

void LogisticRegression::ShowTxtToWindow()//显示文本文件中的内容
{
    QString fileName = "plaintext training.txt";

    if(!fileName.isEmpty())
    {
        QFile *file = new QFile;
        file->setFileName(fileName);
        bool ok = file->open(QIODevice::ReadOnly);
        if(ok)
        {
            QTextStream in(file);
            ui->plainResult->setText(in.readAll());
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

void LogisticRegression::ShowTxtToWindowCip()
{
    QString fileName = "cipher training.txt";

    if(!fileName.isEmpty())
    {
        QFile *file = new QFile;
        file->setFileName(fileName);
        bool ok = file->open(QIODevice::ReadOnly);
        if(ok)
        {
            QTextStream in(file);
            ui->cResult->setText(in.readAll());
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

void LogisticRegression::on_return_2_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}

void LogisticRegression::on_file_clicked()
{
    //定义文件对话框类
    QFileDialog *fileDialog = new QFileDialog(this);
    //定义文件对话框标题
    fileDialog->setWindowTitle(tr("选择数据集"));
    //设置默认文件路径
    fileDialog->setDirectory(".");
    //设置可以选择多个文件,默认为只能选择一个文件QFileDialog::ExistingFiles
    fileDialog->setFileMode(QFileDialog::ExistingFiles);
    //设置视图模式
    fileDialog->setViewMode(QFileDialog::Detail);
    //打印所有选择的文件的路径
    QStringList fileNames;
    if(fileDialog->exec())
    {
        fileNames = fileDialog->selectedFiles();
    }

    QString QString_fileNames = fileNames.join(",");

    QString curPath = QDir::currentPath();
    QString relPath = QString_fileNames.mid(curPath.length()+1);

    QByteArray ba = relPath.toLatin1();
    strcpy(filename,ba.data());
    cout<<filename<<endl;
}

void LogisticRegression::on_comboBox_activated(const QString &arg1)
{
    QMap<QString, int> map_polydeg;
    map_polydeg.insert("3(默认)",3);
    map_polydeg.insert("7",7);
    polydeg = map_polydeg[arg1];
}

void LogisticRegression::on_pushButton_clicked()
{
    testHELR();
}
