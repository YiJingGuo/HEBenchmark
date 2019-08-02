#include "hammingckks.h"
#include "ui_hammingckks.h"
#include "mainwindow.h"

HammingCkks::HammingCkks(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::HammingCkks)
{
    ui->setupUi(this);
    QPalette bgpal = palette();
    bgpal.setColor (QPalette::Background, QColor (0, 0 , 0, 255));
    bgpal.setColor (QPalette::Foreground, QColor (255,255,255,255)); setPalette (bgpal);
}

HammingCkks::~HammingCkks()
{
    delete ui;
}

void HammingCkks::on_security_level_activated(const QString &arg1)
{
    QMap<QString, int> map_security_parameters;
    map_security_parameters.insert("128(默认)",128);
    map_security_parameters.insert("192",192);
    map_security_parameters.insert("256",256);
    security_parameters = map_security_parameters[arg1];
}

void HammingCkks::on_poly_modulus_degree_activated(const QString &arg1)
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

void HammingCkks::on_coeff_modulus_activated(const QString &arg1)
{
    QMap<QString, int> map_coeff_modulus;
    map_coeff_modulus.insert("8192(默认)",8192);
    map_coeff_modulus.insert("16384",16384);
    map_coeff_modulus.insert("32768",32768);
    coeff_modulus = map_coeff_modulus[arg1];
}

void HammingCkks::on_dbc_activated(const QString &arg1)
{
    QMap<QString, int> map_dbc;
    map_dbc.insert("15",15);
    map_dbc.insert("30(默认)",30);
    map_dbc.insert("45",45);
    map_dbc.insert("60",60);
    dbc = map_dbc[arg1];
}

void HammingCkks::on_test_times_textChanged(const QString &arg1)
{
    ui->test_times->setValidator(new QRegExpValidator(QRegExp("[0-9]+$")));
    test_number = arg1.toInt();
}

void HammingCkks::on_start_clicked()
{
    if(security_parameters == 128)
        HammingCkks128(poly_modulus_degree, coeff_modulus, dbc);
    if(security_parameters == 192)
        HammingCkks192(poly_modulus_degree, coeff_modulus, dbc);
    if(security_parameters == 256)
        HammingCkks256(poly_modulus_degree, coeff_modulus, dbc);
}

void HammingCkks::HammingCkks256(int poly_modulus_degree, int coeff_modulus, int dbc)
{
    if(coeff_modulus == 8192)
    coeff_modulus = 16384;

    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_256(coeff_modulus));
    auto context = SEALContext::Create (parms);

    QString result = "";
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_key_sum(0);
    print_parameters(context);

    result += "Generating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_key_sum += time_diff;
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_key_sum += time_diff;
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
    time_key_sum += time_diff;
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
    time_key_sum += time_diff;
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_sub_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rescale_sum(0);
    chrono::microseconds time_rotate_sum(0);
    chrono::microseconds time_mod_switch_sum(0);
    chrono::microseconds time_plain_sum(0);


    long cipher_size = 0;
    long plain_size = 0;

    double scale = pow(2,60);

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> date1;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
       date1.push_back(1 /* static_cast<double>(i)*/);
    }

    vector<double> date2;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
       date2.push_back(0.0);
    }
    vector<double> result_vector(ckks_encoder.slot_count());
    for (int i = 0; i < test_number; i++)
    {
        chrono::microseconds time_hamming_sum(0);
       /*
       [Encoding]
       */
       Plaintext plain1;
       Plaintext plain2;
       time_start = chrono::high_resolution_clock::now();

       ckks_encoder.encode(date1,
           scale, plain1);
       ckks_encoder.encode(date2,
           scale, plain2);
       time_end = chrono::high_resolution_clock::now();
       time_encode_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start)/2;

       /*
       [Encryption]
       */
       Ciphertext cipher1(context);
       Ciphertext cipher2(context);
       time_start = chrono::high_resolution_clock::now();
       encryptor.encrypt(plain1, cipher1);
       encryptor.encrypt(plain2, cipher2);
       time_end = chrono::high_resolution_clock::now();
       time_encrypt_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start)/2;

       /*
       [sub]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.sub_inplace (cipher1,cipher2);
       time_end = chrono::high_resolution_clock::now();
       time_sub_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Square]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.square_inplace(cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_square_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Relinearize]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.relinearize_inplace(cipher1, relin_keys);
       time_end = chrono::high_resolution_clock::now();
       time_relinearize_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Rescale]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.rescale_to_next_inplace(cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_rescale_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [mod_switch_to_next_inplace]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.mod_switch_to_next_inplace (cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_mod_switch_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);

       /*
       [rotate]
       */
       int rotate_steps = log2 (poly_modulus_degree/2);
       time_start = chrono::high_resolution_clock::now();
       for (int i=0;i<rotate_steps;++i) {
           Ciphertext temp;
           evaluator.rotate_vector(cipher1,1<<i,gal_keys,temp);
           evaluator.add_inplace (cipher1,temp);
       }
       time_end = chrono::high_resolution_clock::now();
       time_rotate_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);

       hamming_time.push_back(time_hamming_sum);

       stringstream ss;
       cipher1.save (ss);
       cipher_size = ss.str ().length ();
       /*
       [Decryption]
       */
       Plaintext plain(poly_modulus_degree, 0);
       time_start = chrono::high_resolution_clock::now();
       decryptor.decrypt(cipher1, plain);
       time_end = chrono::high_resolution_clock::now();
       time_decrypt_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);

       /*
       [Decoding]
       */
       time_start = chrono::high_resolution_clock::now();
       ckks_encoder.decode(plain, result_vector);
       time_end = chrono::high_resolution_clock::now();
       time_decode_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);

       /*********************测试明文hamming效率********************/
       vector<double> vec1;
       for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
       {
           vec1.push_back(1 /* static_cast<double>(i)*/);
       }
       vector<double> vec2;
       for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
       {
           vec2.push_back(0.0);
       }
       time_start = chrono::high_resolution_clock::now();
       //vec1 = vec1-vec2;
       transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
       //vec1 = vec1*vec1;
       transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
       for (int i=0;i<rotate_steps;++i) {
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
       plain_size = vec1.size ();

    }

    auto avg_encode = time_encode_sum.count() / test_number;
    auto avg_encrypt = time_encrypt_sum.count() / test_number;
    auto avg_sub = time_sub_sum.count() / test_number;
    auto avg_square = time_square_sum.count() / test_number;
    auto avg_relinearize = time_relinearize_sum.count() / test_number;
    auto avg_rescale = time_rescale_sum.count() / test_number;
    auto avg_mod_switch = time_mod_switch_sum.count() / test_number;

    auto avg_rotate = time_rotate_sum.count() / test_number;
    auto avg_decrypt = time_decrypt_sum.count() / test_number;
    auto avg_decode = time_decode_sum.count() / test_number;
    auto avg_plain_hamming = time_plain_sum.count ()/test_number;
    auto avg_hamming = avg_sub+avg_square+avg_relinearize+avg_mod_switch+avg_rescale+avg_rotate;

    result += "Average encode: ";
    result += QString::number(avg_encode);
    result += " microseconds\n";

    result += "Average encrypt: ";
    result += QString::number(avg_encrypt);
    result += " microseconds\n";

    result += "Average sub: ";
    result += QString::number(avg_sub);
    result += " microseconds\n";

    result += "Average square: ";
    result += QString::number(avg_square);
    result += " microseconds\n";

    result += "Average relinearize: ";
    result += QString::number(avg_relinearize);
    result += " microseconds\n";

    result += "Average rescale: ";
    result += QString::number(avg_rescale);
    result += " microseconds\n";

    result += "Average mod_switch: ";
    result += QString::number(avg_mod_switch);
    result += " microseconds\n";

    result += "Average rotate vector: ";
    result += QString::number(avg_rotate);
    result += " microseconds\n";

    result += "Average decode: ";
    result += QString::number(avg_decode);
    result += " microseconds\n";

    result += "Average decrypt: ";
    result += QString::number(avg_decrypt);
    result += " microseconds\n";

    result += "Average hamming: ";
    result += QString::number(avg_hamming);
    result += " microseconds\n";

    result += "执行总时间(不报括钥匙生成): ";
    result += QString::number(avg_encode+avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_rescale+avg_mod_switch+avg_rotate+avg_decode+avg_decrypt);
    result += " microseconds\n";

    result += "执行总时间(包括钥匙生成):";
    result += QString::number(avg_encode+avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_rescale+avg_mod_switch+avg_rotate+avg_decode+avg_decrypt+time_key_sum.count ());
    result += " microseconds\n";

    result += "明文下hamming时间:";
    result += QString::number(avg_plain_hamming);
    result += " microseconds\n";

    result += "密文和明文时间比(hamming时间比):";
    result += QString::number(avg_hamming);
    result += "/";
    result += QString::number(avg_plain_hamming);
    result += "=";
    result += QString::number(avg_hamming/(double)avg_plain_hamming);
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
}

void HammingCkks::HammingCkks192(int poly_modulus_degree, int coeff_modulus, int dbc)
{
    if(coeff_modulus == 8192)
    coeff_modulus = 16384;

    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_192(coeff_modulus));
    auto context = SEALContext::Create (parms);

    QString result = "";
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_key_sum(0);
    print_parameters(context);

    result += "Generating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_key_sum += time_diff;
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_key_sum += time_diff;
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
    time_key_sum += time_diff;
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
    time_key_sum += time_diff;
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_sub_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rescale_sum(0);
    chrono::microseconds time_rotate_sum(0);
    chrono::microseconds time_mod_switch_sum(0);
    chrono::microseconds time_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    double scale = pow(2,60);

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> date1;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
       date1.push_back(1 /* static_cast<double>(i)*/);
    }

    vector<double> date2;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
       date2.push_back(0.0);
    }
    vector<double> result_vector(ckks_encoder.slot_count());
    for (int i = 0; i < test_number; i++)
    {
       chrono::microseconds time_hamming_sum(0);
       /*
       [Encoding]
       */
       Plaintext plain1;
       Plaintext plain2;
       time_start = chrono::high_resolution_clock::now();

       ckks_encoder.encode(date1,
           scale, plain1);
       ckks_encoder.encode(date2,
           scale, plain2);
       time_end = chrono::high_resolution_clock::now();
       time_encode_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start)/2;

       /*
       [Encryption]
       */
       Ciphertext cipher1(context);
       Ciphertext cipher2(context);
       time_start = chrono::high_resolution_clock::now();
       encryptor.encrypt(plain1, cipher1);
       encryptor.encrypt(plain2, cipher2);
       time_end = chrono::high_resolution_clock::now();
       time_encrypt_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start)/2;

       /*
       [sub]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.sub_inplace (cipher1,cipher2);
       time_end = chrono::high_resolution_clock::now();
       time_sub_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Square]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.square_inplace(cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_square_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Relinearize]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.relinearize_inplace(cipher1, relin_keys);
       time_end = chrono::high_resolution_clock::now();
       time_relinearize_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Rescale]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.rescale_to_next_inplace(cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_rescale_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [mod_switch_to_next_inplace]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.mod_switch_to_next_inplace (cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_mod_switch_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);

       /*
       [rotate]
       */
       int rotate_steps = log2 (poly_modulus_degree/2);
       time_start = chrono::high_resolution_clock::now();
       for (int i=0;i<rotate_steps;++i) {
           Ciphertext temp;
           evaluator.rotate_vector(cipher1,1<<i,gal_keys,temp);
           evaluator.add_inplace (cipher1,temp);
       }
       time_end = chrono::high_resolution_clock::now();
       time_rotate_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);

       hamming_time.push_back(time_hamming_sum);

       stringstream ss;
       cipher1.save (ss);
       cipher_size = ss.str ().length ();
       /*
       [Decryption]
       */
       Plaintext plain(poly_modulus_degree, 0);
       time_start = chrono::high_resolution_clock::now();
       decryptor.decrypt(cipher1, plain);
       time_end = chrono::high_resolution_clock::now();
       time_decrypt_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);

       /*
       [Decoding]
       */
       time_start = chrono::high_resolution_clock::now();
       ckks_encoder.decode(plain, result_vector);
       time_end = chrono::high_resolution_clock::now();
       time_decode_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);

       /*********************测试明文hamming效率********************/
       vector<double> vec1;
       for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
       {
           vec1.push_back(1 /* static_cast<double>(i)*/);
       }
       vector<double> vec2;
       for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
       {
           vec2.push_back(0.0);
       }
       time_start = chrono::high_resolution_clock::now();
       //vec1 = vec1-vec2;
       transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
       //vec1 = vec1*vec1;
       transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
       for (int i=0;i<rotate_steps;++i) {
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
       plain_size = vec1.size ();

    }

    auto avg_encode = time_encode_sum.count() / test_number;
    auto avg_encrypt = time_encrypt_sum.count() / test_number;
    auto avg_sub = time_sub_sum.count() / test_number;
    auto avg_square = time_square_sum.count() / test_number;
    auto avg_relinearize = time_relinearize_sum.count() / test_number;
    auto avg_rescale = time_rescale_sum.count() / test_number;
    auto avg_mod_switch = time_mod_switch_sum.count() / test_number;

    auto avg_rotate = time_rotate_sum.count() / test_number;
    auto avg_decrypt = time_decrypt_sum.count() / test_number;
    auto avg_decode = time_decode_sum.count() / test_number;
    auto avg_plain_hamming = time_plain_sum.count ()/test_number;
    auto avg_hamming = avg_sub+avg_square+avg_relinearize+avg_mod_switch+avg_rescale+avg_rotate;

    result += "Average encode: ";
    result += QString::number(avg_encode);
    result += " microseconds\n";

    result += "Average encrypt: ";
    result += QString::number(avg_encrypt);
    result += " microseconds\n";

    result += "Average sub: ";
    result += QString::number(avg_sub);
    result += " microseconds\n";

    result += "Average square: ";
    result += QString::number(avg_square);
    result += " microseconds\n";

    result += "Average relinearize: ";
    result += QString::number(avg_relinearize);
    result += " microseconds\n";

    result += "Average rescale: ";
    result += QString::number(avg_rescale);
    result += " microseconds\n";

    result += "Average mod_switch: ";
    result += QString::number(avg_mod_switch);
    result += " microseconds\n";

    result += "Average rotate vector: ";
    result += QString::number(avg_rotate);
    result += " microseconds\n";

    result += "Average decode: ";
    result += QString::number(avg_decode);
    result += " microseconds\n";

    result += "Average decrypt: ";
    result += QString::number(avg_decrypt);
    result += " microseconds\n";

    result += "Average hamming: ";
    result += QString::number(avg_hamming);
    result += " microseconds\n";

    result += "执行总时间(不报括钥匙生成): ";
    result += QString::number(avg_encode+avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_rescale+avg_mod_switch+avg_rotate+avg_decode+avg_decrypt);
    result += " microseconds\n";

    result += "执行总时间(包括钥匙生成):";
    result += QString::number(avg_encode+avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_rescale+avg_mod_switch+avg_rotate+avg_decode+avg_decrypt+time_key_sum.count ());
    result += " microseconds\n";

    result += "明文下hamming时间:";
    result += QString::number(avg_plain_hamming);
    result += " microseconds\n";

    result += "密文和明文时间比(hamming时间比):";
    result += QString::number(avg_hamming);
    result += "/";
    result += QString::number(avg_plain_hamming);
    result += "=";
    result += QString::number(avg_hamming/(double)avg_plain_hamming);
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
}

void HammingCkks::HammingCkks128(int poly_modulus_degree, int coeff_modulus, int dbc)
{
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(coeff_modulus));
    auto context = SEALContext::Create (parms);

    QString result = "";
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_key_sum(0);
    print_parameters(context);

    result += "Generating secret/public keys: ";

    KeyGenerator keygen(context);
    result +="Done \n";

    //计算密钥生成时间
    result += "Generating secretkeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto secret_key = keygen.secret_key();
    time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_key_sum += time_diff;
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    //计算公钥生成时间
    result += "Generating publickeys : ";
    time_start = chrono::high_resolution_clock::now();
    auto public_key = keygen.public_key();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    time_key_sum += time_diff;
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
    time_key_sum += time_diff;
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
    time_key_sum += time_diff;
    result += "Done [";
    result += QString::number(time_diff.count());
    result += " microseconds]\n";

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_sub_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rescale_sum(0);
    chrono::microseconds time_rotate_sum(0);
    chrono::microseconds time_mod_switch_sum(0);
    chrono::microseconds time_plain_sum(0);

    long cipher_size = 0;
    long plain_size = 0;

    double scale = pow(2,60);

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> date1;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
       date1.push_back(1 /* static_cast<double>(i)*/);
    }

    vector<double> date2;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
       date2.push_back(0.0);
    }
    vector<double> result_vector(ckks_encoder.slot_count());
    for (int i = 0; i < test_number; i++)
    {
       chrono::microseconds time_hamming_sum(0);
       /*
       [Encoding]
       */
       Plaintext plain1;
       Plaintext plain2;
       time_start = chrono::high_resolution_clock::now();

       ckks_encoder.encode(date1,
           scale, plain1);
       ckks_encoder.encode(date2,
           scale, plain2);
       time_end = chrono::high_resolution_clock::now();
       time_encode_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start)/2;

       /*
       [Encryption]
       */
       Ciphertext cipher1(context);
       Ciphertext cipher2(context);
       time_start = chrono::high_resolution_clock::now();
       encryptor.encrypt(plain1, cipher1);
       encryptor.encrypt(plain2, cipher2);
       time_end = chrono::high_resolution_clock::now();
       time_encrypt_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start)/2;

       /*
       [sub]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.sub_inplace (cipher1,cipher2);
       time_end = chrono::high_resolution_clock::now();
       time_sub_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Square]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.square_inplace(cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_square_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Relinearize]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.relinearize_inplace(cipher1, relin_keys);
       time_end = chrono::high_resolution_clock::now();
       time_relinearize_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [Rescale]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.rescale_to_next_inplace(cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_rescale_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);
       /*
       [mod_switch_to_next_inplace]
       */
       time_start = chrono::high_resolution_clock::now();
       evaluator.mod_switch_to_next_inplace (cipher1);
       time_end = chrono::high_resolution_clock::now();
       time_mod_switch_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);

       /*
       [rotate]
       */
       int rotate_steps = log2 (poly_modulus_degree/2);
       time_start = chrono::high_resolution_clock::now();
       for (int i=0;i<rotate_steps;++i) {
           Ciphertext temp;
           evaluator.rotate_vector(cipher1,1<<i,gal_keys,temp);
           evaluator.add_inplace (cipher1,temp);
       }
       time_end = chrono::high_resolution_clock::now();
       time_rotate_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);
       time_hamming_sum += chrono::duration_cast<
               chrono::microseconds>(time_end - time_start);

       hamming_time.push_back(time_hamming_sum);

       stringstream ss;
       cipher1.save (ss);
       cipher_size = ss.str ().length ();
       /*
       [Decryption]
       */
       Plaintext plain(poly_modulus_degree, 0);
       time_start = chrono::high_resolution_clock::now();
       decryptor.decrypt(cipher1, plain);
       time_end = chrono::high_resolution_clock::now();
       time_decrypt_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);

       /*
       [Decoding]
       */
       time_start = chrono::high_resolution_clock::now();
       ckks_encoder.decode(plain, result_vector);
       time_end = chrono::high_resolution_clock::now();
       time_decode_sum += chrono::duration_cast<
           chrono::microseconds>(time_end - time_start);

       /*********************测试明文hamming效率********************/
       vector<double> vec1;
       for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
       {
           vec1.push_back(1 /* static_cast<double>(i)*/);
       }
       vector<double> vec2;
       for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
       {
           vec2.push_back(0.0);
       }
       time_start = chrono::high_resolution_clock::now();
       //vec1 = vec1-vec2;
       transform(vec1.begin(), vec1.end(), vec2.begin(),vec1.begin (), minus<double>());
       //vec1 = vec1*vec1;
       transform(vec1.begin(), vec1.end(), vec1.begin(),vec1.begin (), multiplies<double>());
       for (int i=0;i<rotate_steps;++i) {
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
       plain_size = vec1.size ();

    }

    auto avg_encode = time_encode_sum.count() / test_number;
    auto avg_encrypt = time_encrypt_sum.count() / test_number;
    auto avg_sub = time_sub_sum.count() / test_number;
    auto avg_square = time_square_sum.count() / test_number;
    auto avg_relinearize = time_relinearize_sum.count() / test_number;
    auto avg_rescale = time_rescale_sum.count() / test_number;
    auto avg_mod_switch = time_mod_switch_sum.count() / test_number;

    auto avg_rotate = time_rotate_sum.count() / test_number;
    auto avg_decrypt = time_decrypt_sum.count() / test_number;
    auto avg_decode = time_decode_sum.count() / test_number;
    auto avg_plain_hamming = time_plain_sum.count ()/test_number;
    auto avg_hamming = avg_sub+avg_square+avg_relinearize+avg_mod_switch+avg_rescale+avg_rotate;

    result += "Average encode: ";
    result += QString::number(avg_encode);
    result += " microseconds\n";

    result += "Average encrypt: ";
    result += QString::number(avg_encrypt);
    result += " microseconds\n";

    result += "Average sub: ";
    result += QString::number(avg_sub);
    result += " microseconds\n";

    result += "Average square: ";
    result += QString::number(avg_square);
    result += " microseconds\n";

    result += "Average relinearize: ";
    result += QString::number(avg_relinearize);
    result += " microseconds\n";

    result += "Average rescale: ";
    result += QString::number(avg_rescale);
    result += " microseconds\n";

    result += "Average mod_switch: ";
    result += QString::number(avg_mod_switch);
    result += " microseconds\n";

    result += "Average rotate vector: ";
    result += QString::number(avg_rotate);
    result += " microseconds\n";

    result += "Average decode: ";
    result += QString::number(avg_decode);
    result += " microseconds\n";

    result += "Average decrypt: ";
    result += QString::number(avg_decrypt);
    result += " microseconds\n";

    result += "Average hamming: ";
    result += QString::number(avg_hamming);
    result += " microseconds\n";

    result += "执行总时间(不报括钥匙生成): ";
    result += QString::number(avg_encode+avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_rescale+avg_mod_switch+avg_rotate+avg_decode+avg_decrypt);
    result += " microseconds\n";

    result += "执行总时间(包括钥匙生成):";
    result += QString::number(avg_encode+avg_encrypt+avg_sub+avg_square+avg_relinearize+avg_rescale+avg_mod_switch+avg_rotate+avg_decode+avg_decrypt+time_key_sum.count ());
    result += " microseconds\n";

    result += "明文下hamming时间:";
    result += QString::number(avg_plain_hamming);
    result += " microseconds\n";

    result += "密文和明文时间比(hamming时间比):";
    result += QString::number(avg_hamming);
    result += "/";
    result += QString::number(avg_plain_hamming);
    result += "=";
    result += QString::number(avg_hamming/(double)avg_plain_hamming);
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
}

void HammingCkks::print_parameters(shared_ptr<SEALContext> context)
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

void HammingCkks::on_return_2_clicked()
{
    MainWindow *win = new MainWindow;
    this->hide();
    win->show();
}

void HammingCkks::charts()
{
    //密文折线图
    QLineSeries *series = new QLineSeries();
    for(int i = 0;i<test_number;i++)
    *series << QPointF(i+1, hamming_time[i].count());

    QLineSeries *series2 = new QLineSeries();
    for(int i = 0;i<test_number;i++)
    *series2 << QPointF(i+1, plain_time[i].count());

    QChart *chart = new QChart();
    chart->legend()->hide();
    chart->addSeries(series);
    chart->addSeries(series2);

    sort(hamming_time.begin(), hamming_time.end());
    sort(plain_time.begin(),plain_time.end());
    auto Ymax = (hamming_time.back().count())*1.2;
    auto Ymin = plain_time[0].count();

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
    hamming_time.clear();
}
