#include "basetestsealbfv.h"
#include "ui_basetestsealbfv.h"
#include "mainwindow.h"
#include <QHBoxLayout>
#include <QValueAxis>

BaseTestSealBFV::BaseTestSealBFV(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BaseTestSealBFV)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
}

BaseTestSealBFV::~BaseTestSealBFV()
{
    delete ui;
}

void BaseTestSealBFV::charts()
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

void BaseTestSealBFV::print_parameters(shared_ptr<SEALContext> context)
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

void BaseTestSealBFV::test_add(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_add_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Add]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);
        Ciphertext encrypted2(context);
        encryptor.encrypt(encoder.encode(i+1), encrypted2);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.add_inplace(encrypted1, encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_add_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start) ;

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_add = time_add_sum.count() / test_number;

    result += "Average add: ";
    temp = QString::number(avg_add);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();

}

void BaseTestSealBFV::test_add_plain(shared_ptr<SEALContext> context)
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

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    Plaintext plain(curr_parms.poly_modulus_degree(), 0);
    batch_encoder.encode(pod_vector, plain);
    for (int i = 0; i < test_number; i++)
    {
        /*
        [Add Plain]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);
        Ciphertext encrypted2(context);
        encryptor.encrypt(encoder.encode(i + 1), encrypted2);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.add_plain_inplace(encrypted1, plain);
        time_end = chrono::high_resolution_clock::now();
        time_add_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

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

    result += "Average add plain: ";
    temp = QString::number(avg_add_plain);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();

}

void BaseTestSealBFV::test_mult(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_mult_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Multiply]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);
        Ciphertext encrypted2(context);
        encryptor.encrypt(encoder.encode(i + 1), encrypted2);
        encrypted1.reserve(3);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_mult_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
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

    result += "Average multiply: ";
    temp = QString::number(avg_mult);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_mult_plain(shared_ptr<SEALContext> context)
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

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    Plaintext plain(curr_parms.poly_modulus_degree(), 0);
    batch_encoder.encode(pod_vector, plain);

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Multiply Plain]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain_inplace(encrypted1, plain);
        time_end = chrono::high_resolution_clock::now();
        time_mult_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_mult_plain = time_mult_plain_sum.count() / test_number;

    result += "Average multiply plain: ";
    temp = QString::number(avg_mult_plain);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_sub(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_sub_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {

        /*
        [Sub]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);
        Ciphertext encrypted2(context);
        encryptor.encrypt(encoder.encode(i+1), encrypted2);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.sub_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_sub_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_sub = time_sub_sum.count() / test_number;

    result += "Average subtraction: ";
    temp = QString::number(avg_sub);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_sub_plain(shared_ptr<SEALContext> context)
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

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
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
        encryptor.encrypt(encoder.encode(i), encrypted1);
        Ciphertext encrypted2(context);
        encryptor.encrypt(encoder.encode(i + 1), encrypted2);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.sub_plain_inplace(encrypted1, plain);
        time_end = chrono::high_resolution_clock::now();
        time_sub_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);

    }
    result += "Initial noise budget: ";
    result += QString::number(noise_budget_initial);
    result += " bits\n";

    result += "The residual noise: ";
    result += QString::number(noise_budget_end);
    result += " bits\n";

    auto avg_sub_plain = time_sub_plain_sum.count() / test_number;

    result += "Average sub plain: ";
    result += QString::number(avg_sub_plain);
    result += " microseconds\n";

    ui->result->setText(result);
    charts();
}

void BaseTestSealBFV::test_square(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_square_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Square]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.square_inplace(encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_square = time_square_sum.count() / test_number;

    result += "Average multiply: ";
    temp = QString::number(avg_square);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_negation(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_negation_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Negation]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.negate_inplace(encrypted1);
        time_end = chrono::high_resolution_clock::now();
        time_negation_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_negation = time_negation_sum.count() / test_number;

    result += "Average negation: ";
    temp = QString::number(avg_negation);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_rotate_rows_one_step(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_rotate_rows_one_step_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Rotate Rows One Step]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_rows_inplace(encrypted1, 1, gal_keys);        time_end = chrono::high_resolution_clock::now();
        time_rotate_rows_one_step_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_rotate_rows_one_step = time_rotate_rows_one_step_sum.count() / test_number;

    result += "Average rotate rows one step: ";
    temp = QString::number(avg_rotate_rows_one_step);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_rotate_rows_random(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_rotate_rows_random_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Rotate Rows Random]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        size_t row_size = batch_encoder.slot_count() / 2;
        int random_rotation = static_cast<int>(rd() % row_size);
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_rows_inplace(encrypted1, random_rotation, gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_rotate_rows_random_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_rotate_rows_random = time_rotate_rows_random_sum.count() / test_number;

    result += "Average rotate rows random: ";
    temp = QString::number(avg_rotate_rows_random);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_rotate_columns(shared_ptr<SEALContext> context)
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

    chrono::microseconds time_rotate_columns_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    for (int i = 0; i < test_number; i++)
    {
        /*
        [Rotate Columns]
        */
        Ciphertext encrypted1(context);
        encryptor.encrypt(encoder.encode(i), encrypted1);

        noise_budget_initial = decryptor.invariant_noise_budget(encrypted1);

        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_columns_inplace(encrypted1, gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_rotate_columns_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        noise_budget_end = decryptor.invariant_noise_budget(encrypted1);
    }

    result += "Initial noise budget: ";
    temp = QString::number(noise_budget_initial);
    result += temp;
    result += " bits\n";

    result += "The residual noise: ";
    temp = QString::number(noise_budget_end);
    result += temp;
    result += " bits\n";

    auto avg_rotate_columns = time_rotate_columns_sum.count() / test_number;

    result += "Average rotate columns: ";
    temp = QString::number(avg_rotate_columns);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);

    charts();
}

void BaseTestSealBFV::test_encryption(shared_ptr<SEALContext> context)
{
    ui->graphicsView->hide();
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

    chrono::microseconds time_encrypt_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    Plaintext plain(curr_parms.poly_modulus_degree(), 0);
    batch_encoder.encode(pod_vector, plain);
    for (int i = 0; i < test_number; i++){
        /*
        [Encryption]
        */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
    }

    auto avg_encrypt = time_encrypt_sum.count() / test_number;

    result += "Average encrypt: ";
    temp = QString::number(avg_encrypt);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
}

void BaseTestSealBFV::test_decryption(shared_ptr<SEALContext> context)
{
    ui->graphicsView->hide();

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

    chrono::microseconds time_decrypt_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    Plaintext plain(curr_parms.poly_modulus_degree(), 0);
    batch_encoder.encode(pod_vector, plain);
    for (int i = 0; i < test_number; i++){
        /*
        [Encryption]
        */
        Ciphertext encrypted(context);
        encryptor.encrypt(plain, encrypted);
        /*
        [Decryption]
        */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(encrypted, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        if (plain2 != plain)
        {
            throw runtime_error("Encrypt/decrypt failed. Something is wrong.");
        }
    }

    auto avg_decrypt = time_decrypt_sum.count() / test_number;

    result += "Average decrypt: ";
    temp = QString::number(avg_decrypt);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
}

void BaseTestSealBFV::test_batching(shared_ptr<SEALContext> context)
{
    ui->graphicsView->hide();

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

    chrono::microseconds time_batch_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";


    for (int i = 0; i < test_number; i++){
        /*
        [Batching]
        */
        Plaintext plain(curr_parms.poly_modulus_degree(), 0);
        time_start = chrono::high_resolution_clock::now();
        batch_encoder.encode(pod_vector, plain);
        time_end = chrono::high_resolution_clock::now();
        time_batch_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
    }

    auto avg_batch = time_batch_sum.count() / test_number;

    result += "Average batch: ";
    temp = QString::number(avg_batch);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
}

void BaseTestSealBFV::test_unbatching(shared_ptr<SEALContext> context)
{
    ui->graphicsView->hide();

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

    chrono::microseconds time_unbatch_sum(0);

    /*
    Populate a vector of values to batch.
    */
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < batch_encoder.slot_count(); i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    result += "\n";

    Plaintext plain(curr_parms.poly_modulus_degree(), 0);
    batch_encoder.encode(pod_vector, plain);
    for (int i = 0; i < test_number; i++){

        /*
        [Unbatching]
        */
        vector<uint64_t> pod_vector2(batch_encoder.slot_count());
        time_start = chrono::high_resolution_clock::now();
        batch_encoder.decode(plain, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_unbatch_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);
        if (pod_vector2 != pod_vector)
        {
            throw runtime_error("Batch/unbatch failed. Something is wrong.");
        }
    }

    auto avg_unbatch = time_unbatch_sum.count() / test_number;

    result += "Average batch: ";
    temp = QString::number(avg_unbatch);
    result += temp;
    result += " microseconds\n";

    ui->result->setText(result);
}

void BaseTestSealBFV::BaseBFV128(int poly_modulus_degree, int coeff_modulus, int plain_modulus)
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
    if(test_type == "Encryption测试")
        test_encryption(SEALContext::Create(parms));
    if(test_type == "Decryption测试")
        test_decryption(SEALContext::Create(parms));
    if(test_type == "Batching测试")
        test_batching(SEALContext::Create(parms));
    if(test_type == "Unbatching测试")
        test_unbatching(SEALContext::Create(parms));
}

void BaseTestSealBFV::BaseBFV192(int poly_modulus_degree, int coeff_modulus, int plain_modulus)
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
    if(test_type == "Encryption测试")
        test_encryption(SEALContext::Create(parms));
    if(test_type == "Decryption测试")
        test_decryption(SEALContext::Create(parms));
    if(test_type == "Batching测试")
        test_batching(SEALContext::Create(parms));
    if(test_type == "Unbatching测试")
        test_unbatching(SEALContext::Create(parms));
}

void BaseTestSealBFV::BaseBFV256(int poly_modulus_degree, int coeff_modulus, int plain_modulus)
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
    if(test_type == "Encryption测试")
        test_encryption(SEALContext::Create(parms));
    if(test_type == "Decryption测试")
        test_decryption(SEALContext::Create(parms));
    if(test_type == "Batching测试")
        test_batching(SEALContext::Create(parms));
    if(test_type == "Unbatching测试")
        test_unbatching(SEALContext::Create(parms));
}

void BaseTestSealBFV::on_TestType_activated(const QString &arg1)
{
    test_type = arg1;
}

void BaseTestSealBFV::on_ToBeginTesting_clicked()
{
    if (security_parameters == 128)
        BaseBFV128(poly_modulus_degree, coeff_modulus, plain_modulus);
    if (security_parameters == 192)
        BaseBFV192(poly_modulus_degree, coeff_modulus, plain_modulus);
    if (security_parameters == 256)
        BaseBFV256(poly_modulus_degree, coeff_modulus, plain_modulus);
}

void BaseTestSealBFV::on_Return_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}

void BaseTestSealBFV::on_lineEdit_textChanged(const QString &arg1)
{
    ui->lineEdit->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    test_number = arg1.toInt();
}

void BaseTestSealBFV::on_security_parameters_activated(const QString &arg1)
{
    QMap<QString, int> map_security_parameters;
    map_security_parameters.insert("128(默认)",128);
    map_security_parameters.insert("192",192);
    map_security_parameters.insert("256",256);
    security_parameters = map_security_parameters[arg1];
}

void BaseTestSealBFV::on_poly_modulus_degree_activated(const QString &arg1)
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

void BaseTestSealBFV::on_coeff_modulus_activated(const QString &arg1)
{
    QMap<QString, int> map_coeff_modulus;
    map_coeff_modulus.insert("4096(默认)",4096);
    map_coeff_modulus.insert("8192",8192);
    map_coeff_modulus.insert("16384",16384);
    map_coeff_modulus.insert("32768",32768);
    coeff_modulus = map_coeff_modulus[arg1];
}

void BaseTestSealBFV::on_plain_modulus_activated(const QString &arg1)
{
    QMap<QString, int> map_plain_modulus;
    map_plain_modulus.insert("786433(默认)",786433);
    plain_modulus = map_plain_modulus[arg1];
}
