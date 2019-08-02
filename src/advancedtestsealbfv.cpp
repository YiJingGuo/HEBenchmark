#include "advancedtestsealbfv.h"
#include "ui_advancedtestsealbfv.h"
#include "mainwindow.h"
AdvancedTestSealBFV::AdvancedTestSealBFV(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AdvancedTestSealBFV)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
}

AdvancedTestSealBFV::~AdvancedTestSealBFV()
{
    delete ui;
}

void AdvancedTestSealBFV::on_return_2_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}

void AdvancedTestSealBFV::on_security_level_activated(const QString &arg1)
{
    QMap<QString, int> map_security_parameters;
    map_security_parameters.insert("128(默认)",128);
    map_security_parameters.insert("192",192);
    map_security_parameters.insert("256",256);
    security_parameters = map_security_parameters[arg1];
}

void AdvancedTestSealBFV::on_poly_modulus_degree_activated(const QString &arg1)
{
    QMap<QString, int> map_poly_modulus_degree;
    map_poly_modulus_degree.insert("1024(默认)",1024);
    map_poly_modulus_degree.insert("2048",2048);
    map_poly_modulus_degree.insert("4096",4096);
    map_poly_modulus_degree.insert("8192",8192);
    map_poly_modulus_degree.insert("16384",16384);
    map_poly_modulus_degree.insert("32768",32768);
    poly_modulus_degree = map_poly_modulus_degree[arg1];
}

void AdvancedTestSealBFV::on_coeff_modulus_activated(const QString &arg1)
{
    QMap<QString, int> map_coeff_modulus;
    map_coeff_modulus.insert("4096(默认)",4096);
    map_coeff_modulus.insert("8192",8192);
    map_coeff_modulus.insert("16384",16384);
    map_coeff_modulus.insert("32768",32768);
    coeff_modulus = map_coeff_modulus[arg1];
}

void AdvancedTestSealBFV::on_plain_modulus_activated(const QString &arg1)
{
    QMap<QString, int> map_plain_modulus;
    map_plain_modulus.insert("786433(默认)",786433);
    plain_modulus = map_plain_modulus[arg1];
}

void AdvancedTestSealBFV::ShowTxtToWindowPlain()//显示文本文件中的内容
{
    QString fileName = "plain_begin.txt";

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


void AdvancedTestSealBFV::ShowTxtToWindowPlainEnd()
{
    QString fileName = "plain_end.txt";

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

void AdvancedTestSealBFV::on_test_type_activated(const QString &arg1)
{
    test_type = arg1;
}

void AdvancedTestSealBFV::on_lineEdit_textChanged(const QString &arg1)
{
    ui->lineEdit->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    test_number = arg1.toInt();
}

void AdvancedTestSealBFV::AdvancedBFV128(int poly_modulus_degree, int coeff_modulus, int plain_modulus)
{
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(coeff_modulus));
    parms.set_plain_modulus(plain_modulus);

    if(test_type == "Add测试")
        test_add(SEALContext::Create(parms));
    if(test_type == "Add Plain测试")
        test_add_plain(SEALContext::Create(parms));
    if(test_type == "Mult测试")
        test_mult(SEALContext::Create(parms));
    if(test_type == "Mult Plain测试")
        test_mult_plain(SEALContext::Create(parms));
    if(test_type == "Sub测试")
        test_sub(SEALContext::Create(parms));
    if(test_type == "Sub Plain测试")
        test_sub_plain(SEALContext::Create(parms));
    if(test_type == "Square测试")
        test_square(SEALContext::Create(parms));
    if(test_type == "Negation测试")
        test_negation(SEALContext::Create(parms));
    if(test_type == "Rotate rows one step测试")
        test_rotate_rows_one_step(SEALContext::Create(parms));
    if(test_type == "Rotate rows random测试")
        test_rotate_rows_random(SEALContext::Create(parms));
    if(test_type == "Rotate columns测试")
        test_rotate_columns(SEALContext::Create(parms));
}

void AdvancedTestSealBFV::AdvancedBFV192(int poly_modulus_degree, int coeff_modulus, int plain_modulus)
{
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_192(coeff_modulus));
    parms.set_plain_modulus(plain_modulus);

    if(test_type == "Add测试")
        test_add(SEALContext::Create(parms));
    if(test_type == "Add Plain测试")
        test_add_plain(SEALContext::Create(parms));
    if(test_type == "Mult测试")
        test_mult(SEALContext::Create(parms));
    if(test_type == "Mult Plain测试")
        test_mult_plain(SEALContext::Create(parms));
    if(test_type == "Sub测试")
        test_sub(SEALContext::Create(parms));
    if(test_type == "Sub Plain测试")
        test_sub_plain(SEALContext::Create(parms));
    if(test_type == "Square测试")
        test_square(SEALContext::Create(parms));
    if(test_type == "Negation测试")
        test_negation(SEALContext::Create(parms));
    if(test_type == "Rotate rows one step测试")
        test_rotate_rows_one_step(SEALContext::Create(parms));
    if(test_type == "Rotate rows random测试")
        test_rotate_rows_random(SEALContext::Create(parms));
    if(test_type == "Rotate columns测试")
        test_rotate_columns(SEALContext::Create(parms));
}

void AdvancedTestSealBFV::AdvancedBFV256(int poly_modulus_degree, int coeff_modulus, int plain_modulus)
{
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_256(coeff_modulus));
    parms.set_plain_modulus(plain_modulus);

    if(test_type == "Add测试")
        test_add(SEALContext::Create(parms));
    if(test_type == "Add Plain测试")
        test_add_plain(SEALContext::Create(parms));
    if(test_type == "Mult测试")
        test_mult(SEALContext::Create(parms));
    if(test_type == "Mult Plain测试")
        test_mult_plain(SEALContext::Create(parms));
    if(test_type == "Sub测试")
        test_sub(SEALContext::Create(parms));
    if(test_type == "Sub Plain测试")
        test_sub_plain(SEALContext::Create(parms));
    if(test_type == "Square测试")
        test_square(SEALContext::Create(parms));
    if(test_type == "Negation测试")
        test_negation(SEALContext::Create(parms));
    if(test_type == "Rotate rows one step测试")
        test_rotate_rows_one_step(SEALContext::Create(parms));
    if(test_type == "Rotate rows random测试")
        test_rotate_rows_random(SEALContext::Create(parms));
    if(test_type == "Rotate columns测试")
        test_rotate_columns(SEALContext::Create(parms));
}

void AdvancedTestSealBFV::on_start_clicked()
{
    if (security_parameters == 128)
        AdvancedBFV128(poly_modulus_degree, coeff_modulus, plain_modulus);
    if (security_parameters == 192)
        AdvancedBFV192(poly_modulus_degree, coeff_modulus, plain_modulus);
    if (security_parameters == 256)
        AdvancedBFV256(poly_modulus_degree, coeff_modulus, plain_modulus);
}

int op_sum (int i, int j)
{
    return i+j;
}
int op_negation(int i, int j)
{
    return -i;
}

void AdvancedTestSealBFV::test_add(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    result += QString::number(dbc);
    result += "): \n";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_add_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    vector<uint64_t> pod_vector;
    random_device rd;

    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    batch_encoder.encode(pod_vector,plain_matrix);

    plain_size = pod_vector.size ();

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Add]
        */
        Ciphertext encrypted1(context);

        if(YesOrNoBatch){
            encryptor.encrypt(plain_matrix,encrypted1);
        }else{
            encryptor.encrypt(encoder.encode(pod_vector.front()), encrypted1);
        }

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.add_inplace(encrypted1, encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_add_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start) ;
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }

        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(rd() % plain_size_max);
        }
        vector<double> vec2;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec2.push_back(rd() % plain_size_max);
        }

        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), op_sum);
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_add = time_add_sum.count() / test_number;
    auto avg_add_plain = time_add_plain_sum.count() / test_number;

    auto ratio  = avg_add/(double)avg_add_plain;

    result += "Average add: ";
    result += QString::number(avg_add);
    result += " microseconds\n";

    result += "Average plain-text addition time: ";
    result += QString::number(avg_add_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_add_plain(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    QString temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_add_plain_sum(0);
    chrono::microseconds time_add_plain_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }


    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    plain_size = pod_vector.size ();

    result += "\n";
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Add Plain]
        */
        Ciphertext encrypted1(context);
        if(YesOrNoBatch){
            encryptor.encrypt(plain_matrix,encrypted1);
        }else{
            encryptor.encrypt(encoder.encode(pod_vector.front()), encrypted1);
        }

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.add_plain_inplace(encrypted1, plain_matrix);
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }

        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1 /* static_cast<double>(i)*/);
        }
        vector<double> vec2;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec2.push_back(0.0);
        }
        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), op_sum);
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

    }
    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_add_plain = time_add_plain_sum.count() / test_number;
    auto avg_add_plain_plain = time_add_plain_plain_sum.count() / test_number;

    auto ratio  = avg_add_plain/(double)avg_add_plain_plain;

    result += "Average add plain: ";
    temp = QString::number(avg_add_plain);
    result += temp;
    result += " microseconds\n";

    result += "Average plain-text addition time: ";
    temp = QString::number(avg_add_plain_plain);
    result += temp;
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    temp = QString::number(ratio);
    result += temp;
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";


    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_mult(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    QString temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_mult_sum(0);
    chrono::microseconds time_mult_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;
    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    vector<uint64_t> pod_vector2;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector2.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","a",stdout);
        cout<<"*"<<endl;
        cout<<pod_vector2<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","a",stdout);
        cout<<"*"<<endl;
        cout<<pod_vector2[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    Plaintext plain_matrix2;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector2,plain_matrix2);
    }else {
        encoder.encode(pod_vector2[0],plain_matrix2);
    }

    plain_size = pod_vector.size ();

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Multiply]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix,encrypted1);
        Ciphertext encrypted2(context);
        encryptor.encrypt(plain_matrix2,encrypted2);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_mult_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }

        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        vector<double> vec2;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec2.push_back(0.0);
        }
        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
        time_end = chrono::high_resolution_clock::now();
        time_mult_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_mult = time_mult_sum.count() / test_number;
    auto avg_mult_plain = time_mult_plain_sum.count() / test_number;

    auto ratio  = avg_mult/(double)avg_mult_plain;

    result += "Average multiply: ";
    result += QString::number(avg_mult);
    result += " microseconds\n";

    result += "Average plain-text multiply time: ";
    result += QString::number(avg_mult_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_mult_plain(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    QString temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_mult_plain_sum(0);
    chrono::microseconds time_mult_plain_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    vector<uint64_t> pod_vector2;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector2.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","a",stdout);
        cout<<"*"<<endl;
        cout<<pod_vector2<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","a",stdout);
        cout<<"*"<<endl;
        cout<<pod_vector2[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    Plaintext plain_matrix2;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector2,plain_matrix2);
    }else {
        encoder.encode(pod_vector2[0],plain_matrix2);
    }

    plain_size = pod_vector.size ();
    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Multiply Plain]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix,encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain_inplace(encrypted1, plain_matrix2);
        time_end = chrono::high_resolution_clock::now();
        time_mult_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }

        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        vector<double> vec2;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec2.push_back(0.0);
        }
        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
        time_end = chrono::high_resolution_clock::now();
        time_mult_plain_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_mult_plain = time_mult_plain_sum.count() / test_number;
    auto avg_mult_plain_plain = time_mult_plain_plain_sum.count() / test_number;

    auto ratio  = avg_mult_plain/(double)avg_mult_plain_plain;

    result += "Average multiply plain: ";
    result += QString::number(avg_mult_plain);
    result += " microseconds\n";

    result += "Average plain-text multiply time: ";
    result += QString::number(avg_mult_plain_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_sub(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    QString temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_sub_sum(0);
    chrono::microseconds time_sub_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    vector<uint64_t> pod_vector2;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector2.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","a",stdout);
        cout<<"-"<<endl;
        cout<<pod_vector2<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","a",stdout);
        cout<<"-"<<endl;
        cout<<pod_vector2[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    batch_encoder.encode(pod_vector,plain_matrix);

    Plaintext plain_matrix2;
    batch_encoder.encode(pod_vector2,plain_matrix2);

    plain_size = pod_vector.size ();

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {

        /*
        [Sub]
        */
        Ciphertext encrypted1(context);
        if(YesOrNoBatch){
            encryptor.encrypt(plain_matrix,encrypted1);
        }else{
            encryptor.encrypt(encoder.encode(pod_vector.front()), encrypted1);
        }

        Ciphertext encrypted2(context);
        if(YesOrNoBatch){
            encryptor.encrypt(plain_matrix2,encrypted2);
        }else{
            encryptor.encrypt(encoder.encode(pod_vector2.front()), encrypted2);
        }

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.sub_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_sub_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }

        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        vector<double> vec2;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec2.push_back(0.0);
        }
        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
        time_end = chrono::high_resolution_clock::now();
        time_sub_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_sub = time_sub_sum.count() / test_number;
    auto avg_sub_plain = time_sub_plain_sum.count() / test_number;

    auto ratio  = avg_sub/(double)avg_sub_plain;

    result += "Average sub: ";
    result += QString::number(avg_sub);
    result += " microseconds\n";

    result += "Average plain-text subtraction time: ";
    result += QString::number(avg_sub_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    temp = QString::number(ratio);
    result += temp;
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_sub_plain(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    QString temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_sub_plain_sum(0);
    chrono::microseconds time_sub_plain_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;
    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    vector<uint64_t> pod_vector2;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector2.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","a",stdout);
        cout<<"-"<<endl;
        cout<<pod_vector2<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","a",stdout);
        cout<<"-"<<endl;
        cout<<pod_vector2[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }
    Plaintext plain_matrix2;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector2,plain_matrix2);
    }else {
        encoder.encode(pod_vector2[0],plain_matrix2);
    }

    result += "\n";

    Plaintext plain(curr_parms.poly_modulus_degree(), 0);
    batch_encoder.encode(pod_vector, plain);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Sub Plain]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix,encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.sub_plain_inplace(encrypted1, plain_matrix2);
        time_end = chrono::high_resolution_clock::now();
        time_sub_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }

        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1 );
        }
        vector<double> vec2;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec2.push_back(0.0);
        }
        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
        time_end = chrono::high_resolution_clock::now();
        time_sub_plain_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }
    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_sub_plain = time_sub_plain_sum.count() / test_number;
    auto avg_sub_plain_plain = time_sub_plain_plain_sum.count() / test_number;

    auto ratio  = avg_sub_plain/(double)avg_sub_plain_plain;

    result += "Average sub plain: ";
    result += QString::number(avg_sub_plain);
    result += " microseconds\n";

    result += "Average plain-text subtraction time: ";
    result += QString::number(avg_sub_plain_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_square(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_square_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;
    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Square]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix,encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.square_inplace(encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }
        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
        time_end = chrono::high_resolution_clock::now();
        time_square_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_square = time_square_sum.count() / test_number;
    auto avg_square_plain = time_square_plain_sum.count() / test_number;
    auto ratio  = avg_square/(double)avg_square_plain;

    result += "Average square: ";
    result += QString::number(avg_square);
    result += " microseconds\n";

    result += "Average plain-text square time: ";
    result += QString::number(avg_square_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_negation(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();
    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_negation_sum(0);
    chrono::microseconds time_negation_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    plain_size = pod_vector.size ();

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Negation]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix, encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.negate_inplace(encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_negation_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }
        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        vector<double> vec2;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec2.push_back(0.0);
        }
        plain_size = vec1.size ();
        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), op_negation);
        time_end = chrono::high_resolution_clock::now();
        time_negation_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_negation = time_negation_sum.count() / test_number;
    auto avg_negation_plain = time_negation_plain_sum.count() / test_number;
    auto ratio  = avg_negation/(double)avg_negation_plain;

    result += "Average negation: ";
    result += QString::number(avg_negation);
    result += " microseconds\n";

    result += "Average plain-text negation time: ";
    result += QString::number(avg_negation_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_rotate_rows_one_step(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_rotate_rows_one_step_sum(0);
    chrono::microseconds time_rotate_rows_one_step_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    plain_size = pod_vector.size ();

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Rotate Rows One Step]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix, encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_rows_inplace(encrypted1, 1, gal_keys);        time_end = chrono::high_resolution_clock::now();
        time_rotate_rows_one_step_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }
        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        plain_size = vec1.size ();
        vector<double> temp;
        time_start = chrono::high_resolution_clock::now();
        rotate_copy(vec1.begin (),vec1.begin ()+1,vec1.end (),back_inserter (temp));
        time_end = chrono::high_resolution_clock::now();
        time_rotate_rows_one_step_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_rotate_rows_one_step = time_rotate_rows_one_step_sum.count() / test_number;
    auto avg_rotate_rows_one_step_plain = time_rotate_rows_one_step_plain_sum.count() / test_number;
    auto ratio  = avg_rotate_rows_one_step/(double)avg_rotate_rows_one_step_plain;

    result += "Average rotate rows one step: ";
    result += QString::number(avg_rotate_rows_one_step);
    result += " microseconds\n";

    result += "Average plain-text rotate rows one step time: ";
    result += QString::number(avg_rotate_rows_one_step_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::test_rotate_rows_random(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_rotate_rows_random_sum(0);
    chrono::microseconds time_rotate_rows_random_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;
    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    plain_size = pod_vector.size ();

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Rotate Rows Random]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix, encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        size_t row_size = batch_encoder.slot_count() / 2;
        int random_rotation = static_cast<int>(rd() % row_size);
        freopen("plain_end.txt","w",stdout);
        cout <<"旋转" <<random_rotation <<"位"<< endl;
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_rows_inplace(encrypted1, random_rotation, gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_rotate_rows_random_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","a",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","a",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }
        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        plain_size = vec1.size ();
        vector<double> temp;
        time_start = chrono::high_resolution_clock::now();

        rotate_copy(vec1.begin (),vec1.begin ()+random_rotation,vec1.end (),back_inserter (temp));
        time_end = chrono::high_resolution_clock::now();
        time_rotate_rows_random_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_rotate_rows_random = time_rotate_rows_random_sum.count() / test_number;
    auto avg_rotate_rows_random_plain = time_rotate_rows_random_plain_sum.count() / test_number;
    auto ratio  = avg_rotate_rows_random/(double)avg_rotate_rows_random_plain;

    result += "Average rotate rows random: ";
    result += QString::number(avg_rotate_rows_random);
    result += " microseconds\n";

    result += "Average plain-text rotate rows random time: ";
    result += QString::number(avg_rotate_rows_random_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();

}

void AdvancedTestSealBFV::test_rotate_columns(shared_ptr<SEALContext> context)
{
    ui->graphicsView->show();
    chrono::high_resolution_clock::time_point time_start, time_end;

    QString result = "";

    print_parameters(context);
    auto &curr_parms = context->context_data()->parms();
    auto &plain_modulus = curr_parms.plain_modulus();

    /*
    Set up keys.
    */
    result += "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    result += "Done\n" ;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    /*
    生成relinearization keys时间.
    */
    int dbc = DefaultParams::dbc_max();
    result += "Generating relinearization keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    /*
    生成Galois keys时间.
    */
    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.";
        return;
    }
    result += "Generating Galois keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto gal_keys = keygen.galois_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    IntegerEncoder encoder(context);

    chrono::microseconds time_rotate_columns_sum(0);
    chrono::microseconds time_rotate_columns_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_size_max);
    }

    if(YesOrNoBatch){
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector<<endl;
        ShowTxtToWindowPlain();
    }else{
        freopen("plain_begin.txt","w",stdout);
        cout<<pod_vector[0]<<endl;
        ShowTxtToWindowPlain();
    }

    Plaintext plain_matrix;
    if(YesOrNoBatch){
        batch_encoder.encode(pod_vector,plain_matrix);
    }else {
        encoder.encode(pod_vector[0],plain_matrix);
    }

    plain_size = pod_vector.size ();

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Rotate Columns]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(plain_matrix, encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_columns_inplace(encrypted1, gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_rotate_columns_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);

        if(YesOrNoBatch){
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            freopen("plain_end.txt","w",stdout);
            cout << pod_result << endl;
            ShowTxtToWindowPlainEnd();
        }else{
            freopen("plain_end.txt","w",stdout);
            cout << encoder.decode_int32(plain_result)<< endl;
            ShowTxtToWindowPlainEnd();
        }
        stringstream ss;
        encrypted1.save (ss);
        cipher_size = ss.str ().length ();

        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        plain_size = vec1.size ();
        vector<double> temp;
        time_start = chrono::high_resolution_clock::now();
        rotate_copy(vec1.begin (),vec1.begin ()+1,vec1.end (),back_inserter (temp));
        time_end = chrono::high_resolution_clock::now();
        time_rotate_columns_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_rotate_columns = time_rotate_columns_sum.count() / test_number;
    auto avg_rotate_columns_plain = time_rotate_columns_plain_sum.count() / test_number;
    auto ratio  = avg_rotate_columns/(double)avg_rotate_columns_plain;

    result += "Average rotate columns time: ";
    result += QString::number(avg_rotate_columns);
    result += " microseconds\n";

    result += "Average plain-text rotate columns plain time: ";
    result += QString::number(avg_rotate_columns_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    result += "密文和明文的大小比:";
    result += QString::number(cipher_size);
    result += "/";
    result += QString::number(plain_size);
    result += "=";
    result += QString::number(cipher_size/(double)plain_size);
    result += "\n";

    ui->result->setText(result);
    charts();
    charts_contrast();
}

void AdvancedTestSealBFV::charts()
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

void AdvancedTestSealBFV::charts_contrast()
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
    }

    if(plain_time[0].count() > cipher_time[0].count()){
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

    chart->setTitle("密文运算时间与明文运算时间对比");

    ui->graphicsView_2->setChart(chart);
    ui->graphicsView_2->setRenderHint(QPainter::Antialiasing);

    plain_time.clear();
    cipher_time.clear();

}

void AdvancedTestSealBFV::print_parameters(shared_ptr<SEALContext> context)
{
    QString result = "";

    // Verify parameters
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    QString scheme_name;
    switch (context_data.parms().scheme())
    {
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }

    result += "/ Encryption parameters:\n";
    result += "| scheme: ";
    result += scheme_name;
    result += "\n| poly_modulus_degree: ";
    int temp_int;
    temp_int = context_data.parms().poly_modulus_degree();
    QString temp = QString::number(temp_int);
    result += temp;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    result += "\n| coeff_modulus size: ";
    temp_int = context_data.
            total_coeff_modulus_bit_count();
    temp = QString::number(temp_int);
    result += temp;
    result += " bits\n";

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV)
    {
        result += "| plain_modulus: ";
        temp_int = context_data.
                parms().plain_modulus().value();
        temp = QString::number(temp_int);
        result += temp;
    }

    result += "\n\\ noise_standard_deviation: ";
    temp_int = context_data.
            parms().noise_standard_deviation();
    temp = QString::number(temp_int);
    result += temp;
    ui->param->setText(result);
}

void AdvancedTestSealBFV::on_radioButton_clicked(bool checked)
{
    YesOrNoBatch = checked;
}

void AdvancedTestSealBFV::on_plain_size_textChanged(const QString &arg1)
{
    ui->lineEdit->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    plain_size_max = arg1.toInt();
}
