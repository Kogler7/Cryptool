#pragma once
extern const unsigned char sTab[16][16];
extern const unsigned char rsTab[16][16];
extern const unsigned char mixArray[4][4];
extern const unsigned int Rcon[11];
int addRoundKey(unsigned char(*pArr)[4], unsigned char(*exKeyArr)[44], unsigned int col);
int byteSub(unsigned char* pArr);
int invByteSub(unsigned char* cArr);
int shiftRows(unsigned int* pArr);
int invShiftRows(unsigned int* cArr);
char gfMultiply(unsigned char numL, unsigned char numR);
int mixColumn(unsigned char(*pArr)[4]);
int keyByteSub(unsigned char(*exKeyArr)[44], unsigned int nCol);
int keyExtendCol(unsigned char(*exKeyArr)[44], unsigned int nCol);
int keyExpansion(const unsigned char(*usrKeyArr)[4], unsigned char(*exKeyArr)[44]);
void aes_ecb_encrypt(unsigned char(*pArr)[4], unsigned char(*exKeyArr)[44]);
void aes_ecb_decrypt(unsigned char(*cArr)[4], unsigned char(*exKeyArr)[44]);