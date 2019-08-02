#include "basetestseal.h"
#include "mainwindow.h"
#include "ui_basetestseal.h"


BaseTestSeal::BaseTestSeal(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::BaseTestSeal)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
    ui->label_20->hide();
    ui->label_21->hide();
}

BaseTestSeal::~BaseTestSeal()
{
    delete ui;

}

void BaseTestSeal::charts_contrast()
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

    auto Ymax = (cipher_time.back().count())*1.1;
    auto Ymin = plain_time[0].count();
    if(plain_time.back().count() > (cipher_time.back().count())*1.1){
        Ymax = (plain_time.back().count())*1.1;
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

    ui->graphicsView->setChart(chart);
    ui->graphicsView->setRenderHint(QPainter::Antialiasing);

    plain_time.clear();
    cipher_time.clear();
}

void BaseTestSeal::print_parameters(shared_ptr<SEALContext> context)
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

    result += "\\ noise_standard_deviation: ";
    temp_int = context_data.
            parms().noise_standard_deviation();
    temp = QString::number(temp_int);
    result += temp;
    ui->param->setText(result);
}

void BaseTestSeal::test_add(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();

    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";


    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    result += QString::number(dbc);
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_add_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    Plaintext plain2(poly_modulus_degree, 0);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Add]
        */
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);
        Ciphertext encrypted2(context);
        ckks_encoder.encode(i + 1, plain2);
        encryptor.encrypt(plain2, encrypted2);

        time_start = chrono::high_resolution_clock::now();
        evaluator.add_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_add_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(0);
        }
        vector<double> vec2;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec2.push_back(1);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), plus<double>());
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

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

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_add_plain(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();

    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_add_plain_sum(0);
    chrono::microseconds time_add_plain_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Add Plain]
        */
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.add_plain_inplace(encrypted1, plain);
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(0);
        }
        vector<double> vec2;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec2.push_back(1);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), plus<double>());
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_add_plain = time_add_plain_sum.count() / test_number;
    auto avg_add_plain_plain = time_add_plain_plain_sum.count() / test_number;

    auto ratio  = avg_add_plain/(double)avg_add_plain_plain;

    result += "Average add plain: ";
    result += QString::number(avg_add_plain);
    result += " microseconds\n";

    result += "Average plain-text addition time: ";
    result += QString::number(avg_add_plain_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_mult(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_multiply_sum(0);
    chrono::microseconds time_multiply_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    Plaintext plain2(poly_modulus_degree, 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);
        Ciphertext encrypted2(context);
        ckks_encoder.encode(i + 1, plain2);
        encryptor.encrypt(plain2, encrypted2);
        /*
        [Multiply]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(0);
        }
        vector<double> vec2;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec2.push_back(1);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), multiplies<double>());
        time_end = chrono::high_resolution_clock::now();
        time_multiply_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_multiply = time_multiply_sum.count() / test_number;
    auto avg_multiply_plain = time_multiply_plain_sum.count() / test_number;

    auto ratio  = avg_multiply/(double)avg_multiply_plain;

    result += "Average multiply: ";
    result += QString::number(avg_multiply);
    result += " microseconds\n";

    result += "Average plain-text multiply time: ";
    result += QString::number(avg_multiply_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_mult_plain(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_multiply_plain_sum(0);
    chrono::microseconds time_multiply_plain_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Multiply Plain]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain_inplace(encrypted1, plain);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(0);
        }
        vector<double> vec2;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec2.push_back(1);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), multiplies<double>());
        time_end = chrono::high_resolution_clock::now();
        time_multiply_plain_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_multiply_plain = time_multiply_plain_sum.count() / test_number;
    auto avg_multiply_plain_plain = time_multiply_plain_plain_sum.count() / test_number;

    auto ratio  = avg_multiply_plain/(double)avg_multiply_plain_plain;

    result += "Average multiply plain: ";
    result += QString::number(avg_multiply_plain);
    result += " microseconds\n";

    result += "Average plain-text multiply time: ";
    result += QString::number(avg_multiply_plain_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_sub(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_sub_sum(0);
    chrono::microseconds time_sub_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    Plaintext plain2(poly_modulus_degree, 0);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Sub]
        */
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);
        Ciphertext encrypted2(context);
        ckks_encoder.encode(i + 1, plain2);
        encryptor.encrypt(plain2, encrypted2);

        time_start = chrono::high_resolution_clock::now();
        evaluator.sub_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_sub_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(0);
        }
        vector<double> vec2;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec2.push_back(1);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
        time_end = chrono::high_resolution_clock::now();
        time_sub_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_sub = time_sub_sum.count() / test_number;
    auto avg_sub_plain = time_sub_plain_sum.count() / test_number;

    auto ratio  = avg_sub/(double)avg_sub_plain;

    result += "Average sub: ";
    result += QString::number(avg_sub);
    result += " microseconds\n";

    result += "Average plain-text sub time: ";
    result += QString::number(avg_sub_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_sub_plain(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_sub_plain_sum(0);
    chrono::microseconds time_sub_plain_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Sub Plain]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.sub_plain_inplace(encrypted1, plain);
        time_end = chrono::high_resolution_clock::now();
        time_sub_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(0);
        }
        vector<double> vec2;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec2.push_back(1);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
        time_end = chrono::high_resolution_clock::now();
        time_sub_plain_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_sub_plain = time_sub_plain_sum.count() / test_number;
    auto avg_sub_plain_plain = time_sub_plain_plain_sum.count() / test_number;

    auto ratio  = avg_sub_plain/(double)avg_sub_plain_plain;

    result += "Average sub plain: ";
    result += QString::number(avg_sub_plain);
    result += " microseconds\n";

    result += "Average plain-text sub time: ";
    result += QString::number(avg_sub_plain_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_square(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_square_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Square]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.square_inplace(encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(0);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
        time_end = chrono::high_resolution_clock::now();
        time_square_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

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

    ui->result->setText(result);
    charts_contrast();
}

auto op_negation(double i, double j)
{
    return -i;
}

void BaseTestSeal::test_negation(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_negation_sum(0);
    chrono::microseconds time_negation_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Negation]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.negate_inplace(encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_negation_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }
        vector<double> vec2;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec2.push_back(0.0);
        }

        time_start = chrono::high_resolution_clock::now();
        transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), op_negation);
        time_end = chrono::high_resolution_clock::now();
        time_negation_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

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

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_rotate_vector(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_rotate_vector_sum(0);
    chrono::microseconds time_rotate_vector_plain_sum(0);


    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Rotate Vector]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector_inplace(encrypted1,1,gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_rotate_vector_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }

        vector<double> temp;
        time_start = chrono::high_resolution_clock::now();
        rotate_copy(vec1.begin (),vec1.begin ()+1,vec1.end (),back_inserter (temp));
        time_end = chrono::high_resolution_clock::now();
        time_rotate_vector_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_rotate_vector = time_rotate_vector_sum.count() / test_number;
    auto avg_rotate_vector_plain = time_rotate_vector_plain_sum.count() / test_number;

    auto ratio  = avg_rotate_vector/(double)avg_rotate_vector_plain;

    result += "Average rotate vector: ";
    result += QString::number(avg_rotate_vector);
    result += " microseconds\n";

    result += "Average plain-text rotate vector time: ";
    result += QString::number(avg_rotate_vector_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_rotate_vector_random(shared_ptr<SEALContext> context, int dbc)
{
    ui->label_16->show();
    ui->label_17->show();
    ui->label_18->show();
    ui->label_19->show();
    ui->label_20->hide();
    ui->label_21->hide();
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_rotate_vector_random_sum(0);
    chrono::microseconds time_rotate_vector_random_plain_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Rotate Vector random]
        */
        int random_rotation = static_cast<int>(rd() % ckks_encoder.slot_count());
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector_inplace(encrypted1, random_rotation, gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_rotate_vector_random_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        cipher_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
        //计算明文运算时间
        vector<double> vec1;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            vec1.push_back(1);
        }

        vector<double> temp;
        time_start = chrono::high_resolution_clock::now();

        rotate_copy(vec1.begin (),vec1.begin ()+random_rotation,vec1.end (),back_inserter (temp));
        time_end = chrono::high_resolution_clock::now();
        time_rotate_vector_random_plain_sum +=chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) ;
        plain_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_rotate_vector_random = time_rotate_vector_random_sum.count() / test_number;
    auto avg_rotate_vector_random_plain = time_rotate_vector_random_plain_sum.count() / test_number;

    auto ratio  = avg_rotate_vector_random/(double)avg_rotate_vector_random_plain;

    result += "Average rotate vector random: ";
    result += QString::number(avg_rotate_vector_random);
    result += " microseconds\n";

    result += "Average plain-text rotate vector random time: ";
    result += QString::number(avg_rotate_vector_random_plain);
    result += " microseconds\n";

    result += "密文运算与明文运算时间比: ";
    result += QString::number(ratio);
    result += "\n";

    ui->result->setText(result);
    charts_contrast();
}

void BaseTestSeal::test_relinearize(shared_ptr<SEALContext> context, int dbc)
{
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_relinearize_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Relinearize]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(encrypted1,relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_relinearize_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        run_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }
    auto avg_relinearize = time_relinearize_sum.count() / test_number;

    result += "Average relinearize: ";
    temp = QString::number(avg_relinearize);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
    ui->label_16->hide();
    ui->label_17->hide();
    ui->label_18->hide();
    ui->label_19->hide();
    ui->label_20->show();
    ui->label_21->show();
    charts_time();
}

void BaseTestSeal::charts_time()
{
    //坐标点导入
    QLineSeries *series = new QLineSeries();

    for(int i = 0;i<test_number;i++)
    *series << QPointF(i+1, run_time[i].count());

    QChart *chart = new QChart();
    chart->legend()->hide();
    chart->addSeries(series);

    sort(run_time.begin(), run_time.end());

    auto Ymax = (run_time.back().count())*1.1;
    auto Ymin = run_time[0].count();

    QValueAxis *axisX = new QValueAxis();//轴变量、数据系列变量，都不能声明为局部临时变量
    QValueAxis *axisY = new QValueAxis();//创建X/Y轴
    axisX->setRange(1, test_number);
    axisY->setRange(Ymin, Ymax);//设置X/Y显示的区间
    chart->setAxisX(axisX);
    chart->setAxisY(axisY);//设置chart的坐标轴
    series->attachAxis(axisX);//连接数据集与坐标轴。
    series->attachAxis(axisY);

    chart->setTitle("运行时间");

    ui->graphicsView->setChart(chart);
    ui->graphicsView->setRenderHint(QPainter::Antialiasing);

    run_time.clear();
}

void BaseTestSeal::test_rescale(shared_ptr<SEALContext> context, int dbc)
{

    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_rescale_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);

        /*
        [Rescale]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.rescale_to_next_inplace(encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_rescale_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        run_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_rescale = time_rescale_sum.count() / test_number;

    result += "Average rescale: ";
    temp = QString::number(avg_rescale);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
    ui->label_16->hide();
    ui->label_17->hide();
    ui->label_18->hide();
    ui->label_19->hide();
    ui->label_20->show();
    ui->label_21->show();
    charts_time();
}

void BaseTestSeal::test_encryption(shared_ptr<SEALContext> context, int dbc)
{

    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encryption_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    ckks_encoder.encode(pod_vector,
        static_cast<double>(curr_parms.coeff_modulus().back().value()), plain);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Encryption]
        */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encryption_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        run_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_encryption = time_encryption_sum.count() / test_number;

    result += "Average encryption: ";
    temp = QString::number(avg_encryption);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
    ui->label_16->hide();
    ui->label_17->hide();
    ui->label_18->hide();
    ui->label_19->hide();
    ui->label_20->show();
    ui->label_21->show();
    charts_time();
}

void BaseTestSeal::test_decryption(shared_ptr<SEALContext> context, int dbc)
{
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_decryption_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    ckks_encoder.encode(pod_vector,
        static_cast<double>(curr_parms.coeff_modulus().back().value()), plain);
    Ciphertext encrypted(context);
    encryptor.encrypt(plain, encrypted);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Decryption]
        */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(encrypted, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decryption_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        run_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_decryption = time_decryption_sum.count() / test_number;

    result += "Average decryption: ";
    temp = QString::number(avg_decryption);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
    ui->label_16->hide();
    ui->label_17->hide();
    ui->label_18->hide();
    ui->label_19->hide();
    ui->label_20->show();
    ui->label_21->show();
    charts_time();
}

void BaseTestSeal::test_encoding(shared_ptr<SEALContext> context, int dbc)
{
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encoding_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Encoding]
        */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector,
            static_cast<double>(curr_parms.coeff_modulus().back().value()), plain);
        time_end = chrono::high_resolution_clock::now();
        time_encoding_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        run_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_encoding = time_encoding_sum.count() / test_number;

    result += "Average encoding: ";
    temp = QString::number(avg_encoding);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
    ui->label_16->hide();
    ui->label_17->hide();
    ui->label_18->hide();
    ui->label_19->hide();
    ui->label_20->show();
    ui->label_21->show();
    charts_time();
}

void BaseTestSeal::test_decoding(shared_ptr<SEALContext> context, int dbc)
{
    QString result = "";

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);

    auto &curr_parms = context->context_data()->parms();
    size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

    result += "\nGenerating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";
    ui->result->setText(result);

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    int time_temp = time_diff.count();
    QString temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    //生成密钥交换钥匙的时间
    result += "Generating relinearization keys (dbc = ";
    temp = QString::number(dbc);
    result += temp;
    result += "): ";
    time_start = chrono::high_resolution_clock::now();
    auto relin_keys = keygen.relin_keys(dbc);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_temp = time_diff.count();
    temp = QString::number(time_temp);
    result += "Done [";
    result += temp;
    result += " microseconds]\n";
    ui->result->setText(result);

    if (!context->context_data()->qualifiers().using_batching)
    {
        result += "Given encryption parameters do not support batching.\n";
        ui->result->setText(result);
        return;
    }

    //生成galois钥匙的时间
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
    ui->result->setText(result);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_decode_sum(0);

    double scale;
    if (coeff_modulus == 4096){
        scale = pow(2,54);
    }else {
        scale = pow(2,60);
    }

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    result += "Running tests \n";
    ui->result->setText(result);

    Plaintext plain(curr_parms.poly_modulus_degree() *
        curr_parms.coeff_modulus().size(), 0);
    Ciphertext encrypted(context);
    ckks_encoder.encode(pod_vector,
        static_cast<double>(curr_parms.coeff_modulus().back().value()), plain);
    vector<double> pod_vector2(ckks_encoder.slot_count());
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Decoding]
        */
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.decode(plain, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        run_time.push_back(chrono::duration_cast<
                              chrono::microseconds>(time_end - time_start));
    }

    auto avg_decode = time_decode_sum.count() / test_number;

    result += "Average decoding: ";
    temp = QString::number(avg_decode);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
    ui->label_16->hide();
    ui->label_17->hide();
    ui->label_18->hide();
    ui->label_19->hide();
    ui->label_20->show();
    ui->label_21->show();
    charts_time();
}

void BaseTestSeal::BaseCkks128(int poly_modulus_degree, int coeff_modulus, int dbc)
{
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(coeff_modulus));
    auto context = SEALContext::Create(parms);
    if(test_type == "Add测试")
        test_add(context, dbc);
    if(test_type == "Add Plain测试")
        test_add_plain(context, dbc);
    if(test_type == "Mult测试")
        test_mult(context, dbc);
    if(test_type == "Mult Plain测试")
        test_mult_plain(context, dbc);
    if(test_type == "Sub测试")
        test_sub(context, dbc);
    if(test_type == "Sub Plain测试")
        test_sub_plain(context, dbc);
    if(test_type == "Square测试")
        test_square(context, dbc);
    if(test_type == "Negation测试")
        test_negation(context, dbc);
    if(test_type == "Rotate Vector测试")
        test_rotate_vector(context, dbc);
    if(test_type == "Rotate Vector Random测试")
        test_rotate_vector_random(context, dbc);
    if(test_type == "Relinearize测试")
        test_relinearize(context, dbc);
    if(test_type == "Rescale测试")
        test_rescale(context, dbc);
    if(test_type == "Encryption测试")
        test_encryption(context, dbc);
    if(test_type == "Decryption测试")
        test_decryption(context, dbc);
    if(test_type == "Encoding测试")
        test_encoding(context, dbc);
    if(test_type == "Decoding测试")
        test_decoding(context, dbc);
}

void BaseTestSeal::BaseCkks192(int poly_modulus_degree, int coeff_modulus, int dbc)
{
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_192(coeff_modulus));
    auto context = SEALContext::Create(parms);
    if(test_type == "Add测试")
        test_add(context, dbc);
    if(test_type == "Add Plain测试")
        test_add_plain(context, dbc);
    if(test_type == "Mult测试")
        test_mult(context, dbc);
    if(test_type == "Mult Plain测试")
        test_mult_plain(context, dbc);
    if(test_type == "Sub测试")
        test_sub(context, dbc);
    if(test_type == "Sub Plain测试")
        test_sub_plain(context, dbc);
    if(test_type == "Square测试")
        test_square(context, dbc);
    if(test_type == "Negation测试")
        test_negation(context, dbc);
    if(test_type == "Rotate Vector测试")
        test_rotate_vector(context, dbc);
    if(test_type == "Rotate Vector Random测试")
        test_rotate_vector_random(context, dbc);
    if(test_type == "Relinearize测试")
        test_relinearize(context, dbc);
    if(test_type == "Rescale测试")
        test_rescale(context, dbc);
    if(test_type == "Encryption测试")
        test_encryption(context, dbc);
    if(test_type == "Decryption测试")
        test_decryption(context, dbc);
    if(test_type == "Encoding测试")
        test_encoding(context, dbc);
    if(test_type == "Decoding测试")
        test_decoding(context, dbc);
}

void BaseTestSeal::BaseCkks256(int poly_modulus_degree, int coeff_modulus, int dbc)
{
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_256(coeff_modulus));
    auto context = SEALContext::Create(parms);
    if(test_type == "Add测试")
        test_add(context, dbc);
    if(test_type == "Add Plain测试")
        test_add_plain(context, dbc);
    if(test_type == "Mult测试")
        test_mult(context, dbc);
    if(test_type == "Mult Plain测试")
        test_mult_plain(context, dbc);
    if(test_type == "Sub测试")
        test_sub(context, dbc);
    if(test_type == "Sub Plain测试")
        test_sub_plain(context, dbc);
    if(test_type == "Square测试")
        test_square(context, dbc);
    if(test_type == "Negation测试")
        test_negation(context, dbc);
    if(test_type == "Rotate Vector测试")
        test_rotate_vector(context, dbc);
    if(test_type == "Rotate Vector Random测试")
        test_rotate_vector_random(context, dbc);
    if(test_type == "Relinearize测试")
        test_relinearize(context, dbc);
    if(test_type == "Rescale测试")
        test_rescale(context, dbc);
    if(test_type == "Encryption测试")
        test_encryption(context, dbc);
    if(test_type == "Decryption测试")
        test_decryption(context, dbc);
    if(test_type == "Encoding测试")
        test_encoding(context, dbc);
    if(test_type == "Decoding测试")
        test_decoding(context, dbc);
}

void BaseTestSeal::on_pushButton_clicked()
{
    if (security_parameters == 128)
        BaseCkks128(poly_modulus_degree, coeff_modulus, dbc);
    if (security_parameters == 192)
        BaseCkks128(poly_modulus_degree, coeff_modulus, dbc);
    if (security_parameters == 256)
        BaseCkks128(poly_modulus_degree, coeff_modulus, dbc);
}

void BaseTestSeal::on_comboBox_activated(const QString &arg1)
{
    QMap<QString, int> map_security_parameters;
    map_security_parameters.insert("128(默认)",128);
    map_security_parameters.insert("192",192);
    map_security_parameters.insert("256",256);
    security_parameters = map_security_parameters[arg1];
}

void BaseTestSeal::on_comboBox_2_activated(const QString &arg1)
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

void BaseTestSeal::on_comboBox_3_activated(const QString &arg1)
{
    QMap<QString, int> map_coeff_modulus;
    map_coeff_modulus.insert("4096(默认)",4096);
    map_coeff_modulus.insert("8192",8192);
    map_coeff_modulus.insert("16384",16384);
    map_coeff_modulus.insert("32768",32768);
    coeff_modulus = map_coeff_modulus[arg1];
}

void BaseTestSeal::on_comboBox_4_activated(const QString &arg1)
{
    QMap<QString, int> map_dbc;
    map_dbc.insert("15",15);
    map_dbc.insert("30(默认)",30);
    map_dbc.insert("45",45);
    map_dbc.insert("60",60);
    dbc = map_dbc[arg1];
}

void BaseTestSeal::on_pushButton_2_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}

void BaseTestSeal::on_lineEdit_textChanged(const QString &arg1)
{
    ui->lineEdit->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    test_number = arg1.toInt();
}

void BaseTestSeal::on_TestType_activated(const QString &arg1)
{
    test_type = arg1;
}
