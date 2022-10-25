#define _CRT_SECURE_NO_WARNINGS
#include "aes.h"
#include <stdio.h>
#include <string>
#include <iostream>

using namespace std;

int main() {
	//读入文本文件，每一行以16进制解析16个字节的数据
	FILE* fp = fopen("./The Rosy Moon.txt", "r");
	if (fp == NULL) {
		printf("open file error");
		return 0;
	}
	for (int j = 0; j < 10; j++) {
		string s = "./testcase/testcase";
		s.append(string().insert(0, 1, char(j + '0')));
		s.append(string(".txt"));

		cout << s << endl;
		FILE* caseFile = fopen(s.c_str(), "w");
		unsigned char pt[16];
		unsigned char ct[16];
		unsigned char key[16];
		int i = 0;
		while (fread(pt, 1, 16, fp) && i++ < 16);
		while (fread(key, 1, 16, fp) && i++ < 32);

		//将读入的数据写入文件中
		i = 0;
		while (i < 16) {
			fprintf(caseFile, "%02x ", pt[i]);
			printf("%02x ", pt[i++]);
		}
		fprintf(caseFile, "\n\r");
		printf("\n");
		i = 0;
		while (i < 16) {
			fprintf(caseFile, "%02x ", key[i]);
			printf("%02x ", key[i++]);
		}
		fprintf(caseFile, "\n\r");
		printf("\n");

		unsigned char usrKeyArr[4][4];
		unsigned char exKeyArr[4][44];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				usrKeyArr[j][i] = key[i * 4 + j];
			}
		}
		keyExpansion(usrKeyArr, exKeyArr);
		unsigned char pArr[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				pArr[j][i] = pt[i * 4 + j];
			}
		}
		aes_ecb_encrypt(pArr, exKeyArr);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				ct[i * 4 + j] = pArr[j][i];
			}
		}
		i = 0;
		while (i < 16) {
			fprintf(caseFile, "%02x ", ct[i]);
			printf("%02x ", ct[i++]);
		}
		aes_ecb_decrypt(pArr, exKeyArr);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				pt[i * 4 + j] = pArr[j][i];
			}
		}
		i = 0;
		printf("\n");
		while (i < 16) {
			printf("%02x ", pt[i++]);
		}
		printf("\n\n");
		fclose(caseFile);
	}

	fclose(fp);
	return 0;
}