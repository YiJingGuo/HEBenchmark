#-------------------------------------------------
#
# Project created by QtCreator 2019-07-08T04:46:05
#
#-------------------------------------------------

QT       += core gui
QT       += charts
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = HEBenchMark
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++17
CONFIG += thread
SOURCES += \
    advancedtesthelib.cpp \
    advancedtestsealbfv.cpp \
    basetesthelib.cpp \
    generatorthread.cpp \
    hammingckks.cpp \
    hamminghelib.cpp \
        main.cpp \
        mainwindow.cpp \
    basetestseal.cpp \
    basetestsealbfv.cpp \
    parametergenerator.cpp \
    unitex.cpp

HEADERS += \
    advancedtesthelib.h \
    advancedtestsealbfv.h \
    basetesthelib.h \
    generatorthread.h \
    hammingckks.h \
    hamminghelib.h \
        mainwindow.h \
    basetestseal.h \
    basetestsealbfv.h \
    parametergenerator.h \
    unitex.h

FORMS += \
    advancedtesthelib.ui \
    advancedtestsealbfv.ui \
    basetesthelib.ui \
    hammingckks.ui \
    hamminghelib.ui \
        mainwindow.ui \
    basetestseal.ui \
    basetestsealbfv.ui \
    parametergenerator.ui
LIBS += -lseal
LIBS += -lhelib -lntl -lgmp -lm
LIBS += -lpthread
LIBS += -pthread

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    image.qrc
