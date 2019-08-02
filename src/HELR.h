#ifndef LOGISTIC_H_
#define LOGISTIC_H_


#include <iostream>
#include <map>


#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>


#include "HELR/TestScheme.h"
#include "HELR/Cipher.h"
#include "HELR/CZZ.h"
#include "HELR/EvaluatorUtils.h"
#include "HELR/Message.h"
#include "HELR/Params.h"
#include "HELR/PubKey.h"
#include "HELR/Scheme.h"
#include "HELR/SchemeAlgo.h"
#include "HELR/SchemeAux.h"
#include "HELR/SecKey.h"
#include "HELR/StringUtils.h"



#include "Database.h"
#include "LRtest.h"

using namespace std;
using namespace NTL;


class LogReg {
public:

    Scheme& scheme;
    LRpar& LRparams;
    SecKey& secretKey;
    
    
    //! @ constructor
    LogReg(Scheme& scheme, SecKey& secretKey, LRpar& LRparams) : scheme(scheme),  secretKey(secretKey),  LRparams(LRparams) {}
    
    
    //---------------------------------------------------------------------------------------------------
    
    void EncryptData(Cipher*& zTrainCipher,  dMat zTrain);
    //void EncryptData_small(Cipher*& zTrainCipher,  dMat zTrain, LRpar& LRparams, Scheme& scheme);

    void HElogreg(Cipher*& thetaCipher, Cipher*& zTrainCipher,   dMat zTrain);
    
    Cipher* getgrad_deg3(Cipher*& thetaCipher, Cipher*& zTrainCipher);
    Cipher* getgrad_deg7(Cipher*& thetaCipher, Cipher*& zTrainCipher);
    
    static long getctlvl(Cipher& ctxt);
    void show_and_compare(dVec& theta, dMat zTrain, CZZ*& dtheta);

    
};



#endif /* LOGISTIC_H_ */
