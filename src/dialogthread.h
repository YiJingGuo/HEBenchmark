#ifndef DIALOGTHREAD_H
#define DIALOGTHREAD_H

#include <QThread>


class DialogThread : public QThread
{

public:
    DialogThread();
    void closeThread();


protected:
    virtual void run();

private:
    volatile bool isStop;
};

#endif // DIALOGTHREAD_H
