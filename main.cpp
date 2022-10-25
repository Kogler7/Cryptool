#include "Cryptool.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    Cryptool win;
    win.show();
    //testAES();
    return app.exec();
    return 0;
}
