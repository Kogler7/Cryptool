#include "pad.h"

void padPKCS7(unsigned char* pt, int pt_len, int block_size) {
	int pad_len = block_size - pt_len % block_size;
	for (int i = 0; i < pad_len; i++) {
		pt[pt_len + i] = pad_len;
	}
}

int dePadPKCS7(unsigned char* ct, int block_size) {
	int pad_len = ct[block_size - 1];
	for (int i = 0; i < pad_len && i < block_size - 1; i++) {
		ct[block_size - 1 - i] = 0;
	}
	return block_size - pad_len;
}

void padISO9797M2(unsigned char* pt, int pt_len, int block_size) {
	int pad_len = block_size - pt_len % block_size;
	for (int i = 1; i < pad_len; i++) {
		pt[pt_len + i] = 0;
	}
	pt[pt_len] = 0x80;
}

int dePadISO9797M2(unsigned char* ct, int block_size) {
	int pad_len = 0;
	for (int i = 0; i < block_size - 1; i++) {
		if (ct[block_size - 1 - i] == 0x80) {
			pad_len = i + 1;
			break;
		}
	}
	for (int i = 0; i < pad_len; i++) {
		ct[block_size - 1 - i] = 0;
	}
	return block_size - pad_len;
}

void padANSIX923(unsigned char* pt, int pt_len, int block_size) {
	int pad_len = block_size - pt_len % block_size;
	for (int i = 0; i < pad_len; i++) {
		pt[pt_len + i] = 0;
	}
	pt[block_size - 1] = pad_len;
}

int dePadANSIX923(unsigned char* ct, int block_size) {
	int pad_len = ct[block_size - 1];
	for (int i = 0; i < pad_len && i < block_size - 1; i++) {
		ct[block_size - 1 - i] = 0;
	}
	return block_size - pad_len;
}

void pad(unsigned char* pt, int pt_len, int block_size, Padding padding) {
	switch (padding) {
	case PKCS7:
		padPKCS7(pt, pt_len, block_size);
		break;
	case ISO9797M2:
		padISO9797M2(pt, pt_len, block_size);
		break;
	case ANSIX923:
		padANSIX923(pt, pt_len, block_size);
		break;
	default:
		break;
	}
}

int dePad(unsigned char* ct, int block_size, Padding padding) {
	switch (padding) {
	case PKCS7:
		return dePadPKCS7(ct, block_size);
	case ISO9797M2:
		return dePadISO9797M2(ct, block_size);
	case ANSIX923:
		return dePadANSIX923(ct, block_size);
	default:
		return 0;
	}
}