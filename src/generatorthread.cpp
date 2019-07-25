#include "generatorthread.h"
#include "parametergenerator.h"
#include "ui_parametergenerator.h"
#include <QMutex>
#include "unitex.h"

GeneratorThread::GeneratorThread()
{
    isStop = false;
}

void GeneratorThread::closeThread()
{
    isStop = true;
}
void GeneratorThread::getphi(int N){
    phi[1]=1;//φ(1)=1
    for(int i=2;i<=N;i++){
        if(!mark[i]){
            prime[++tot]=i;
            phi[i]=i-1;
        }
        for(int j=1;j<=tot;j++){
            if(i*prime[j]>N) break;
            mark[i*prime[j]]=1;
            if(i%prime[j]==0){
                phi[i*prime[j]]=phi[i]*prime[j];break;
            }
            else phi[i*prime[j]]=phi[i]*phi[prime[j]];
        }
    }
}

int GeneratorThread::isPrime(int p)
{
    int j;
    for ( j=2; j<=sqrt(p); j++ )
    {
        if(p%j==0)    // 如果不为素数返回0
        {
            return 0;
        }
    }
    return 1;    // 反之则返回1
}
//计算ord(p)
long GeneratorThread::multOrd1(long p, long m)
{
    if (GCD(p, m) != 1) return 0;
    p = p % m;
    long ord = 1;
    long val = p;
    while (val != 1) {
        ord++;
        val = MulMod(val, p, m);
    }
    return ord;
}

void GeneratorThread::run()
{
    QString result = "";
    freopen("generator_parm.txt","w",stdout);
    QMutex mutex;
    mutex.lock();
    int pri = Unitex::pri;

    getphi(Unitex::m2);
    if(!isPrime (pri)){
        cout<<"p is not prime"<<endl;
        isStop = true;
    }

    for(int m=Unitex::m1;m<=Unitex::m2 && !isStop;m++){

        long ord_p = multOrd1 (pri,m);
        if(ord_p==0)
            continue;
        long slot = phi[m]/ord_p;
        if(slot >=Unitex::s1 && slot <= Unitex::s2 && !isStop){
            FHEcontext context(m, pri, 1);
            buildModChain(context, 300, 2);
            int securityLevel = context.securityLevel ();
            if(securityLevel >=Unitex::k1 && securityLevel<=Unitex::k2 && !isStop){
            cout<<"m = "<<m<<",phi ( "<<phi[m]<<" ),ord(p) = "<<ord_p<<",slot="<<slot<<endl;
            cout<<"安全等级:"<<securityLevel<<endl;
            }
        }
    }
    mutex.unlock();
    cout<< "stop!"<<endl;
    isStop = false;
}
