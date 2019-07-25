#ifndef GENERATORTHREAD_H
#define GENERATORTHREAD_H

#include<iostream>
#include<cstring>
#include<cstdio>
#include<thread>
#include <NTL/ZZX.h>
#include <helib/FHE.h>
#include <QThread>

using namespace NTL;
using namespace std;

class GeneratorThread : public QThread
{

public:
    GeneratorThread();
    void closeThread();

    int prime[100001],mark[1000001];//prime是素数数组，mark为标记不是素数的数组
    int tot,phi[100001];//phi为φ(),tot为1~i现求出的素数个数

    int isPrime(int p);
    //计算ord(p)
    long multOrd1(long p, long m);
    void getphi(int N);
protected:
    virtual void run();

private:
    volatile bool isStop;
};

#endif // GENERATORTHREAD_H
