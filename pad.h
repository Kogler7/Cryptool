#ifndef __CRYPTOOL_H_
#define __CRYPTOOL_H_
#include "Cryptool.h"
#endif __CRYPTOOL_H_

void padPKCS7(unsigned char* pt, int pt_len, int block_size);
int dePadPKCS7(unsigned char* ct, int block_size);
void padISO9797M2(unsigned char* pt, int pt_len, int block_size);
int dePadISO9797M2(unsigned char* ct, int block_size);
void padANSIX923(unsigned char* pt, int pt_len, int block_size);
int dePadANSIX923(unsigned char* ct, int block_size);
void pad(unsigned char* pt, int pt_len, int block_size, Padding padding);
int dePad(unsigned char* ct, int block_size, Padding padding);
