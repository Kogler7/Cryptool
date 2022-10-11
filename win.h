#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_DesQt.h"
#include "des.h"
#include<QtWidgets/qfiledialog.h>

class CryptoolWindow : public QMainWindow
{
    Q_OBJECT;
    unsigned char key[8] = {0};
    QFileInfo plainFile, cipherFile, keyFile;

public:
    CryptoolWindow(QWidget *parent = nullptr);
    ~CryptoolWindow();
    QString selectFile();
    void yield(QString text);
    void yield(const char* text);
    void selectPlainFile();
    void selectCipherFile();
    void selectKeyFile();
    void start_encrypt();
    void start_decrypt();
    void load_key();
    bool check_key();
    bool encrypt(const char* pt_path, const char* ct_path, unsigned char* key);
    bool decrypt(const char* ct_path, const char* pt_path, unsigned char* key);

private:
    Ui::DesQtClass ui;
};
