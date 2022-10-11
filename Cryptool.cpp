#include "Cryptool.h"

#define get_cstr(qstr) qstr.toLatin1().data()


Cryptool::Cryptool(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	ui.statusLabel->setText(QString("就绪。"));
	ui.keyInput->setText(QString("ABCDEFGH"));
	ui.plainLine->setReadOnly(true);
	ui.cipherLine->setReadOnly(true);
	ui.keyLine->setReadOnly(true);
	connect(ui.pButton, &QPushButton::pressed, this, &Cryptool::selectPlainFile);
	connect(ui.cButton, &QPushButton::pressed, this, &Cryptool::selectCipherFile);
	connect(ui.kButton, &QPushButton::pressed, this, &Cryptool::selectKeyFile);
	connect(ui.encryptBtn, &QPushButton::pressed, this, &Cryptool::start_encrypt);
	connect(ui.decryptBtn, &QPushButton::pressed, this, &Cryptool::start_decrypt);
}

Cryptool::~Cryptool()
{}

void Cryptool::yield(QString text) {
	ui.statusLabel->setText(text);
}

void Cryptool::yield(const char* text) {
	QString txt(text);
	ui.statusLabel->setText(txt);
}

QString Cryptool::selectFile() {
	return QFileDialog::getOpenFileName(
		this, QStringLiteral("文件对话框！"),
		"F:",
		QStringLiteral("明/密文文件(*txt)")
	);
}

void Cryptool::selectPlainFile() {
	plainFile = QFileInfo(selectFile());
	ui.plainLine->setText(plainFile.fileName());
}

void Cryptool::selectCipherFile() {
	cipherFile = QFileInfo(selectFile());
	ui.cipherLine->setText(cipherFile.fileName());
}

void Cryptool::selectKeyFile() {
	keyFile = QFileInfo(selectFile());
	ui.keyLine->setText(keyFile.fileName());
	load_key();
}

void Cryptool::start_encrypt() {
	if (!plainFile.exists()) {
		yield("错误：明文文件不存在！");
		return;
	}
	QString output = plainFile.absolutePath() +
		"/" +
		plainFile.fileName().split('.')[0] +
		"_encrypt.txt";
	bool success = encrypt(
		get_cstr(plainFile.absoluteFilePath()),
		get_cstr(output),
		key
	);
	if (success) yield("加密成功！");
}

void Cryptool::start_decrypt() {
	if (!cipherFile.exists()) {
		yield("错误：密文文件不存在！");
		return;
	}
	QString output = cipherFile.absolutePath() +
		"/" +
		cipherFile.fileName().split('.')[0] +
		"_decrypt.txt";
	bool success = decrypt(
		get_cstr(cipherFile.absoluteFilePath()),
		get_cstr(output),
		key
	);
	if (success) yield("解密成功！");
}

void Cryptool::load_key() {
	FILE* kf = fopen(get_cstr(keyFile.absoluteFilePath()), "r");
	int cnt = fread(key, 1, 8, kf);
	if (cnt < 8) yield("错误：密钥文件不可用！");
	else {
		yield("密钥加载成功！");
		QString qkey;
		for (int i = 0; i < 8; i++) qkey.append((char)key[i]);
		qkey.append('\0');
		ui.keyInput->setText(qkey);
	}
}

bool Cryptool::check_key() {
	QString text = ui.keyInput->text();
	if (text.size() >= 8) {
		for (int i = 0; i < 8; i++)
			key[i] = (unsigned char)text[i].toLatin1();
		return true;
	}
	yield("错误：密钥长度错误。");
	return false;
}

bool Cryptool::encrypt(const char* pt_path, const char* ct_path, unsigned char* key) {
	if (!check_key()) {
		return false;
	}
	symmetric_key skey;
	if (des_setup(key, 8, 16, &skey) == CRYPT_OK) {
		unsigned char plain[8];
		unsigned char cipher[8];
		FILE* pf = fopen(pt_path, "rb");
		FILE* cf = fopen(ct_path, "wb");
		while (1) {
			int cnt = fread(plain, 1, 8, pf);
			if (cnt == 0) {
				break;
			}
			while (cnt < 8)
			{
				plain[cnt++] = 0;
			}
			des_ecb_encrypt((unsigned char*)plain, (unsigned char*)cipher, &skey);
			fwrite(cipher, 1, 8, cf);
		}
		fclose(pf);
		fclose(cf);
		return true;
	}
	else {
		yield("错误：非法密钥");
		return false;
	}
}

bool Cryptool::decrypt(const char* ct_path, const char* pt_path, unsigned char* key) {
	if (!check_key()) {
		return false;
	}
	symmetric_key skey;
	if (des_setup(key, 8, 16, &skey) == CRYPT_OK) {
		unsigned char plain[8];
		unsigned char cipher[8];
		FILE* pf = fopen(pt_path, "wb");
		FILE* cf = fopen(ct_path, "rb");
		while (1) {
			int cnt = fread(cipher, 1, 8, cf);
			if (cnt == 0) {
				break;
			}
			des_ecb_decrypt((unsigned char*)cipher, (unsigned char*)plain, &skey);
			fwrite(plain, 1, 8, pf);
		}
		fclose(pf);
		fclose(cf);
		return true;
	}
	else {
		yield("错误：非法密钥");
		return false;
	}
}