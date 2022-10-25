#include "Cryptool.h"
#include "des.h"
#include "aes.h"
#include "pad.h"

#define get_cstr(qstr) qstr.toLatin1().data()


Cryptool::Cryptool(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	ui.statusLabel->setText(QString("就绪。"));
	ui.keyInput->setText(QString("ABCDEFGHIJKLMNOP"));
	ui.plainLine->setReadOnly(true);
	ui.cipherLine->setReadOnly(true);
	ui.keyLine->setReadOnly(true);
	setWindowTitle("DES/AES加解密工具-V2");
	connect(ui.pButton, &QPushButton::pressed, this, &Cryptool::selectPlainFile);
	connect(ui.cButton, &QPushButton::pressed, this, &Cryptool::selectCipherFile);
	connect(ui.kButton, &QPushButton::pressed, this, &Cryptool::selectKeyFile);
	connect(ui.encryptBtn, &QPushButton::pressed, this, &Cryptool::startEncrypt);
	connect(ui.decryptBtn, &QPushButton::pressed, this, &Cryptool::startDecrypt);
	connect(ui.modeBtn1, &QRadioButton::toggled, [=](bool checked) {
		if (checked) {
			crypMode = DESmode;
			workMode = ECB;
			yield("DES-ECB");
		}
	});
	connect(ui.modeBtn2, &QRadioButton::toggled, [=](bool checked) {
		if (checked) {
			crypMode = DESmode;
			workMode = CBC;
			yield("DES-CBC");
		}
	});
	connect(ui.modeBtn3, &QRadioButton::toggled, [=](bool checked) {
		if (checked) {
			crypMode = DESmode;
			workMode = OFB;
			yield("DES-OFB");
		}
	});
	connect(ui.modeBtn4, &QRadioButton::toggled, [=](bool checked) {
		if (checked) {
			crypMode = AESmode;
			yield("AES");
		}
	});
	connect(ui.paddingBtn1, &QRadioButton::toggled, [=](bool checked) {
		if (checked) {
			padding = PKCS7;
			yield("PKCS#7");
		}
		});
	connect(ui.paddingBtn2, &QRadioButton::toggled, [=](bool checked) {
		if (checked) {
			padding = ISO9797M2;
			yield("ISO-9797-M2");
		}
		});
	connect(ui.paddingBtn3, &QRadioButton::toggled, [=](bool checked) {
		if (checked) {
			padding = ANSIX923;
			yield("ANSI-X9.23");
		}
		});
	ui.modeBtn4->setChecked(true);
	ui.paddingBtn1->setChecked(true);
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
	if (crypMode == AESmode) {
		loadAesKey();
	}
	else {
		loadDesKey();
	}
}

void Cryptool::startEncrypt() {
	if (!plainFile.exists()) {
		yield("错误：明文文件不存在！");
		return;
	}
	QString output = plainFile.absolutePath() +
		"/" +
		plainFile.fileName().split('.')[0] +
		"_encrypt.txt";
	bool success;
	if (crypMode == CrypMode::DESmode) {
		success = encryptDes(get_cstr(plainFile.absoluteFilePath()),
			get_cstr(output),
			desKey);
	}
	else {
		success = encryptAes(get_cstr(plainFile.absoluteFilePath()),
			get_cstr(output),
			aesKey);
	}
	if (success) yield("加密成功！");
}

void Cryptool::startDecrypt() {
	if (!cipherFile.exists()) {
		yield("错误：密文文件不存在！");
		return;
	}
	QString output = cipherFile.absolutePath() +
		"/" +
		cipherFile.fileName().split('.')[0] +
		"_decrypt.txt";
	bool success;
	if (crypMode == CrypMode::DESmode) {
		success = decryptDes(
			get_cstr(cipherFile.absoluteFilePath()),
			get_cstr(output),
			desKey
		);
	}
	else {
		try {
			success = decryptAes(
				get_cstr(cipherFile.absoluteFilePath()),
				get_cstr(output),
				aesKey
			);
		}
		catch (...) {

		}
	}
	if (success) yield("解密成功！");
}

void Cryptool::loadDesKey() {
	FILE* kf = fopen(get_cstr(keyFile.absoluteFilePath()), "r");
	int cnt = fread(desKey, 1, 8, kf);
	if (cnt < 8) yield("错误：密钥文件不可用！");
	else {
		yield("密钥加载成功！");
		QString qkey;
		for (int i = 0; i < 8; i++) qkey.append((char)desKey[i]);
		qkey.append('\0');
		ui.keyInput->setText(qkey);
	}
}

bool Cryptool::checkDesKey() {
	QString text = ui.keyInput->text();
	if (text.size() >= 8) {
		for (int i = 0; i < 8; i++)
			desKey[i] = (unsigned char)text[i].toLatin1();
		return true;
	}
	yield("错误：密钥长度错误。");
	return false;
}

void Cryptool::loadAesKey() {
	FILE* kf = fopen(get_cstr(keyFile.absoluteFilePath()), "r");
	int cnt = fread(aesKey, 1, 16, kf);
	if (cnt < 16) yield("错误：密钥文件不可用！");
	else {
		yield("密钥加载成功！");
		QString qkey;
		for (int i = 0; i < 16; i++) qkey.append((char)aesKey[i]);
		qkey.append('\0');
		ui.keyInput->setText(qkey);
	}
}

bool Cryptool::checkAesKey() {
	QString text = ui.keyInput->text();
	if (text.size() >= 16) {
		for (int i = 0; i < 16; i++)
			aesKey[i] = (unsigned char)text[i].toLatin1();
		return true;
	}
	yield("错误：密钥长度错误。");
	return false;
}

bool Cryptool::encryptDes(const char* pt_path, const char* ct_path, unsigned char* key) {
	if (!checkDesKey()) {
		return false;
	}
	symmetric_key skey;
	if (des_setup(key, 8, 16, &skey) == CRYPT_OK) {
		unsigned char plain[8];
		unsigned char cipher[8] = { 0 };
		FILE* pf = fopen(pt_path, "rb");
		FILE* cf = fopen(ct_path, "wb");
		unsigned char iv[8] = { 0 };
		switch (workMode)
		{
		case ECB:
			while (1) {
				int cnt = fread(plain, 1, 8, pf);
				if (cnt == 0) {
					break;
				}
				if (cnt < 8) {
					pad(plain, cnt, 8, padding);
				}
				des_ecb_encrypt((unsigned char*)plain, (unsigned char*)cipher, &skey);
				fwrite(cipher, 1, 8, cf);
			}
			break;
		case CBC:
			for (int i = 0; i < 8; i++) {
				iv[i] = rand();
			}
			fwrite(iv, 1, 8, cf);
			while (1) {
				int cnt = fread(plain, 1, 8, pf);
				if (cnt == 0) {
					break;
				}
				if (cnt < 8) {
					pad(plain, cnt, 8, padding);
				}
				for (int i = 0; i < 8; i++) {
					plain[i] ^= iv[i];
				}
				des_ecb_encrypt((unsigned char*)plain, (unsigned char*)cipher, &skey);
				for (int i = 0; i < 8; i++) {
					iv[i] = cipher[i];
				}
				fwrite(cipher, 1, 8, cf);
			}
			break;
		case OFB:
			for (int i = 0; i < 8; i++) {
				iv[i] = rand();
			}
			fwrite(iv, 1, 8, cf);
			while (1) {
				int cnt = fread(plain, 1, 1, pf);
				if (cnt == 0) {
					break;
				}
				des_ecb_encrypt((unsigned char*)iv, (unsigned char*)cipher, &skey);
				for (int i = 0; i < 7; i++) {
					iv[i] = iv[i + 1];
				}
				iv[7] = cipher[0];
				cipher[0] ^= plain[0];
				fwrite(cipher, 1, 1, cf);
			}
			break;
		default:
			yield("错误：非法工作模式");
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

bool Cryptool::decryptDes(const char* ct_path, const char* pt_path, unsigned char* key) {
	if (!checkDesKey()) {
		return false;
	}
	symmetric_key skey;
	if (des_setup(key, 8, 16, &skey) == CRYPT_OK) {
		unsigned char plain[8] = { 0 };
		unsigned char cipher[8];
		unsigned char iv[8];
		FILE* pf = fopen(pt_path, "wb");
		FILE* cf = fopen(ct_path, "rb");
		bool sof = true;
		bool eof = false;
		switch (workMode)
		{
		case ECB:
			while (1) {
				int cnt = fread(cipher, 1, 8, cf);
				if (cnt == 0 && !eof) {
					eof = true;
					cnt = dePad(plain, 8, padding);
				}
				if (!sof) fwrite(plain, 1, cnt, pf);
				sof = false;
				if (eof) break;
				des_ecb_decrypt((unsigned char*)cipher, (unsigned char*)plain, &skey);
			}
			break;
		case CBC:
			fread(iv, 1, 8, cf);
			while (1) {
				int cnt = fread(cipher, 1, 8, cf);
				if (cnt == 0 && !eof) {
					eof = true;
					cnt = dePad(plain, 8, padding);
				}
				if (!sof) fwrite(plain, 1, cnt, pf);
				sof = false;
				if (eof) break;
				des_ecb_decrypt((unsigned char*)cipher, (unsigned char*)plain, &skey);
				for (int i = 0; i < 8; i++) {
					plain[i] ^= iv[i];
					iv[i] = cipher[i];
				}
			}
			break;
		case OFB:
			fread(iv, 1, 8, cf);
			while (1) {
				int cnt = fread(cipher, 1, 1, cf);
				if (cnt == 0) {
					break;
				}
				des_ecb_encrypt((unsigned char*)iv, (unsigned char*)plain, &skey);
				for (int i = 0; i < 7; i++) {
					iv[i] = iv[i + 1];
				}
				iv[7] = plain[0];
				plain[0] ^= cipher[0];
				fwrite(plain, 1, 1, pf);
			}
			break;
		default:
			yield("错误：非法工作模式");
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

bool Cryptool::encryptAes(const char* pt_path, const char* ct_path, unsigned char* key) {
	if (!checkAesKey()) {
		return false;
	}
	unsigned char usrKeyArr[4][4];
	unsigned char exKeyArr[4][44];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			usrKeyArr[j][i] = key[i * 4 + j];
		}
	}
	keyExpansion(usrKeyArr, exKeyArr);
	unsigned char plain[16];
	unsigned char cipher[16];
	FILE* pf = fopen(pt_path, "rb");
	FILE* cf = fopen(ct_path, "wb");
	while (1) {
		int cnt = fread(plain, 1, 16, pf);
		if (cnt == 0) {
			break;
		}
		if (cnt < 16) {
			pad(plain, cnt, 16, padding);
		}
		unsigned char pArr[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				pArr[j][i] = plain[i * 4 + j];
			}
		}
		aes_ecb_encrypt(pArr, exKeyArr);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				cipher[i * 4 + j] = pArr[j][i];
			}
		}
		fwrite(cipher, 1, 16, cf);
	}
	fclose(pf);
	fclose(cf);
	return true;
}

bool Cryptool::decryptAes(const char* ct_path, const char* pt_path, unsigned char* key) {
	if (!checkAesKey()) {
		return false;
	}
	unsigned char usrKeyArr[4][4];
	unsigned char exKeyArr[4][44];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			usrKeyArr[j][i] = key[i * 4 + j];
		}
	}
	keyExpansion(usrKeyArr, exKeyArr);
	unsigned char plain[16] = { 0 };
	unsigned char cipher[16];
	unsigned char cArr[4][4];
	FILE* pf = fopen(pt_path, "wb");
	FILE* cf = fopen(ct_path, "rb");
	bool sof = true;
	bool eof = false;
	while (1) {
		int cnt = fread(cipher, 1, 16, cf);
		if (cnt == 0 && !eof) {
			eof = true;
			cnt = dePad(plain, 16, padding);
		}
		if (!sof) fwrite(plain, 1, cnt, pf);
		sof = false;
		if (eof) break;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				cArr[j][i] = cipher[i * 4 + j];
			}
		}
		aes_ecb_decrypt(cArr, exKeyArr);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				plain[i * 4 + j] = cArr[j][i];
			}
		}
	}
	fclose(pf);
	fclose(cf);
	return true;
}