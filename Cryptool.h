#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_Cryptool.h"
#include <QtWidgets/qfiledialog.h>

enum CrypMode {
	DESmode,
	AESmode
};

enum WorkMode {
	ECB,
	CBC,
	OFB
};

enum Padding {
	PKCS7,
	ISO9797M2,
	ANSIX923
};

class Cryptool : public QMainWindow
{
    Q_OBJECT;
    unsigned char desKey[8] = { 0 };
	unsigned char aesKey[16] = { 0 };
    QFileInfo plainFile, cipherFile, keyFile;
	CrypMode crypMode = AESmode;
	WorkMode workMode = ECB;
	Padding padding = PKCS7;
public:
    Cryptool(QWidget* parent = nullptr);
    ~Cryptool();
    QString selectFile();
    void yield(QString text);
    void yield(const char* text);
    void selectPlainFile();
    void selectCipherFile();
    void selectKeyFile();
    void startEncrypt();
    void startDecrypt();
    void loadDesKey();
    bool checkDesKey();
    void loadAesKey();
    bool checkAesKey();
    bool encryptDes(const char* pt_path, const char* ct_path, unsigned char* key);
    bool decryptDes(const char* ct_path, const char* pt_path, unsigned char* key);
    bool encryptAes(const char* pt_path, const char* ct_path, unsigned char* key);
    bool decryptAes(const char* ct_path, const char* pt_path, unsigned char* key);
private:
    Ui::CryptoolClass ui;
};
