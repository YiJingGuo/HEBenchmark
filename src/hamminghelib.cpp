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

void HammingHElib::StartTest()
{
//    // Plaintext prime modulus
//    unsigned  long p = 8191;
//    // Cyclotomic polynomial - defines phi(m)
//    unsigned long m = 32768;
//    // Hensel lifting (default = 1)
//    unsigned long r = 8;
//    // Number of bits of the modulus chain
//    unsigned long bits = 120;
//    // Number of columns of Key-Switching matix (default = 2 or 3)
//    unsigned long c = 2;
//    //cout<<m<<endl;
//    FHEcontext context(m, p, r);

//    chrono::high_resolution_clock::time_point time_start, time_end;

//    buildModChain(context, bits, c);

//    std::cout << "Security: " << context.securityLevel() << std::endl;
//    FHESecKey secret_key(context);
//    cout << "Generating secretkeys : \n";
//    time_start = chrono::high_resolution_clock::now();
//    secret_key.GenSecKey();
//    time_end = chrono::high_resolution_clock::now();
//    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
//    cout << "Done [" << time_diff.count() << " microseconds]" << endl;


//    cout << "addSome1DMatrices : \n";
//    time_start = chrono::high_resolution_clock::now();
//    addSome1DMatrices(secret_key);
//    time_end = chrono::high_resolution_clock::now();
//    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
//    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

//    cout << "Generating publickeys : \n";
//    time_start = chrono::high_resolution_clock::now();
//    const FHEPubKey& public_key = secret_key;
//    time_end = chrono::high_resolution_clock::now();
//    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
//    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

//    const EncryptedArray& ea  = *(context.ea);

//    long nslots = ea.size();

//    std::vector<double> ptxt1(nslots);
//    std::vector<double> ptxt2(nslots);
//    for (int i=0;i<nslots;++i) {
//        ptxt1[i]=1.0;
//        ptxt2[i]=0.0;
//    }
//    int temp = log2 (nslots);
//    Ctxt ctxt1(public_key);
//    Ctxt ctxt2(public_key);

//    chrono::microseconds time_encrypt_sum(0);
//    chrono::microseconds time_decrypt_sum(0);
//    chrono::microseconds time_sub_sum(0);
//    chrono::microseconds time_square_sum(0);
//    chrono::microseconds time_relinearize_sum(0);
//    chrono::microseconds time_rotate_sum(0);
//    chrono::microseconds time_mod_switch_sum(0);
//    int count = 10;
//    vector<double> decrypted;
//    for(int i=0;i<10;++i){

//        time_start = chrono::high_resolution_clock::now();
//        ea.encrypt(ctxt1, public_key, ptxt1);
//        ea.encrypt(ctxt2, public_key, ptxt2);
//        time_end = chrono::high_resolution_clock::now();
//        time_encrypt_sum += chrono::duration_cast<
//                chrono::microseconds>(time_end - time_start)/2;
//        //cout<<"操作前明文noise space:"<<ctxt1.getNoiseBound ()<<endl;
//        time_start = chrono::high_resolution_clock::now();
//        ctxt1 -= ctxt2;
//        time_end = chrono::high_resolution_clock::now();
//        time_sub_sum += chrono::duration_cast<
//                chrono::microseconds>(time_end - time_start);

//        time_start = chrono::high_resolution_clock::now();
//        ctxt1.square ();
//        time_end = chrono::high_resolution_clock::now();
//        time_square_sum += chrono::duration_cast<
//                chrono::microseconds>(time_end - time_start);


//        time_start = chrono::high_resolution_clock::now();
//        ctxt1.reLinearize ();
//        time_end = chrono::high_resolution_clock::now();
//        time_relinearize_sum += chrono::duration_cast<
//                chrono::microseconds>(time_end - time_start);

//        time_start = chrono::high_resolution_clock::now();
//        ctxt1.modSwitchAddedNoiseBound ();
//        time_end = chrono::high_resolution_clock::now();
//        time_mod_switch_sum += chrono::duration_cast<
//                chrono::microseconds>(time_end - time_start);

//        //cout<<"旋转前noise space:"<<ctxt1.getNoiseBound ()<<endl;

//        Ctxt t = ctxt1;
//        time_start = chrono::high_resolution_clock::now();
//        for (int i=0;i<temp;++i) {
//            ea.rotate (ctxt1,1<<i);
//            ctxt1+=t;
//            t = ctxt1;
//        }
//        time_end = chrono::high_resolution_clock::now();
//        time_rotate_sum += chrono::duration_cast<
//                chrono::microseconds>(time_end - time_start);
//        //cout<<"旋转后noise space:"<<ctxt1.getNoiseBound ()<<endl;
//        /*
//        [Decryption]
//        */
//        time_start = chrono::high_resolution_clock::now();
//        ea.decrypt(ctxt1, secret_key, decrypted);
//        time_end = chrono::high_resolution_clock::now();
//        time_decrypt_sum += chrono::duration_cast<
//                chrono::microseconds>(time_end - time_start);
//    }
//    std::cout << "Decrypted Ptxt: " << decrypted << std::endl;
//    //std::cout << "Decrypted result: " << decrypted[2047] << std::endl;
//    auto avg_encrypt = time_encrypt_sum.count() / count;
//    auto avg_sub = time_sub_sum.count() / count;
//    auto avg_square = time_square_sum.count() / count;
//    auto avg_relinearize = time_relinearize_sum.count() / count;
//    auto avg_mod_switch = time_mod_switch_sum.count() / count;

//    auto avg_rotate = time_rotate_sum.count() / count;
//    auto avg_decrypt = time_decrypt_sum.count() / count;

//    auto avg_hamming = avg_sub+avg_square+avg_relinearize+avg_mod_switch+avg_rotate;

//    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
//    cout << "Average sub: " << avg_sub << " microseconds" << endl;
//    cout << "Average square: " << avg_square << " microseconds" << endl;
//    cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
//    cout << "Average mod_switch: " << avg_mod_switch << " microseconds" << endl;
//    cout << "Average rotate vector : " << avg_rotate << " microseconds" << endl;
//    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
//    cout << "Average hamming:" << avg_hamming << " microseconds" << endl;
//    cout <<"执行总时间(不报括钥匙生成):"<<avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_mod_switch+avg_rotate+avg_decrypt<<"  microseconds"<<endl;
//    cout.flush();
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
