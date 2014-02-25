/**
 * Simple File Encryption/Decryption System, C++ version
 *
 * Copyright (c) Brian Chau, 2013-2014
 *
 * me@brianchau.ca
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Author information at http://www.brianchau.ca/
 *
 * hash.cpp
 *
 * Hash functions
 */
#include "hash.h"
#include "util.h"
#include <cstdlib>
const char Hash::VALS_A[16] = {(char)0x34, (char)0xee, (char)0x4e, (char)0xa7,
			       (char)0x03, (char)0x44, (char)0x14, (char)0x07,
			       (char)0xdc, (char)0x97, (char)0x3b, (char)0xed,
			       (char)0x8e, (char)0x8b, (char)0xb0, (char)0xea };
const char Hash::VALS_B[16] = {(char)0x2a, (char)0x04, (char)0x14, (char)0x61,
			       (char)0xc4, (char)0xe9, (char)0xf4, (char)0x3e,
			       (char)0xbb, (char)0xa2, (char)0xb3, (char)0xbc,
			       (char)0xf8, (char)0x1a, (char)0x3c, (char)0xe4 };
const unsigned int Hash::VALS_SHA2_256[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
					      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
					      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
					      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
					      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
					      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
const int Hash::SHIFT_A[16] = {3, 6, 4, 1,
			       7, 2, 0, 5,
			       6, 6, 3, 0,
			       7, 2, 5, 0 };
const int Hash::SHIFT_B[16] = {5, 3, 0, 3,
			       7, 2, 6, 4,
			       4, 1, 2, 6,
			       1, 5, 1, 3 };
char* Hash::arr;
long long Hash::hsize;
char Hash::get(int index, char f) {
	if (index >= hsize) {
		if (index - hsize > 3) throw -1;
		if (f == 'A')
			return index - hsize;
		if (f == 'B') {
			switch (index - hsize) {
				case 0:
					return 0x11;
				case 1:
					return 0x89;
				case 2:
					return 0x2f;
				case 3:
					return 0xe3;
			}
		}
		throw -1;
	}
	return arr[index];
}
char Hash::getSHA2_256(long long index, char* first, char* second, long long firstsize) {
	if (index < firstsize)
		return first[index];
	else
		return second[index-firstsize];
}
char Hash::rotl8(char val, int n) {
	char ls = n;
	char rs = 8 - n;
	unsigned char lm = 0xff << ls;
	unsigned char rm = 0xff >> rs;
	return (char)((((unsigned char)(val) << ls) & lm) + (((unsigned char)(val) >> rs) & rm));
}
unsigned int Hash::rotl32u(unsigned int val, int n) {
	int ls = n;
	int rs = 32 - n;
	unsigned int lm = 0xffffffff << ls;
	unsigned int rm = 0xffffffff >> rs;
	return ((val << ls) & lm) + ((val >> rs) & rm);
}
char Hash::rotr8(char val, int n) {
	char ls = 8 - n;
	char rs = n;
	unsigned char lm = 0xff << ls;
	unsigned char rm = 0xff >> rs;
	return (char)((((unsigned char)(val) << ls) & lm) + (((unsigned char)(val) >> rs) & rm));
}
unsigned int Hash::rotr32u(unsigned int val, int n) {
	int ls = 32 - n;
	int rs = n;
	unsigned int lm = 0xffffffff << ls;
	unsigned int rm = 0xffffffff >> rs;
	return ((val << ls) & lm) + ((val >> rs) & rm);
}
char Hash::func(char a, char c, int x) {
	switch (x) {
		case 0:
			return a ^ c;
		case 1:
			return rotl8(a, 1) + rotl8(c, 7);
		case 2:
			return rotr8(a, 3) ^ rotr8(c, 6);
		case 3:
			return a + c;
	}
	throw -1;
}
int Hash::generateHashA(char* input, long long size) {
	arr = input;
	hsize = size;
	char A = 0x62;
	char B = 0x49;
	char C = 0xfc;
	char D = 0x3f;
	// Get number of iterations
	int iterations = (hsize / 4) + 1;
	for (int i = 0; i < iterations; i++) {
		for (int j = 0; j < 16; j++) {
			int k = 4 * i;
			if (j < 4) {
				k += (11 * j) % 4;
			} else if (j < 8) {
				k += ((7 * j) + 3) % 4;
			} else if (j < 12) {
				k += ((5 * j) + 1) % 4;
			} else {
				k += j % 4;
			}
			char oldA = A;
			A = rotl8((B + D) + get(k, 'A') + VALS_A[j], SHIFT_A[j]);
			B = C ^ oldA;
			C = D;
			D = oldA;
		}
	}
	arr = NULL;
	// return in big endian
	return (((int)A << 24) & 0xff000000) + (((int)B << 16) & 0x00ff0000) + (((int)C << 8) & 0x0000ff00) + (((int)D) & 0x000000ff);
}
int Hash::generateHashB(char* input, long long size) {
	arr = input;
	hsize = size;
	char A = 0x84;
	char B = 0x5d;
	char C = 0x6f;
	char D = 0xff;
	// Get number of iterations
	int iterations = ((hsize - 1) / 4) + 1;
	for (int i = 0; i < iterations; i++) {
		for (int j = 0; j < 16; j++) {
			int k = 4 * i;
			if (j < 4) {
				k += j % 4;
			} else if (j < 8) {
				k += ((13 * j) + 2) % 4;
			} else if (j < 12) {
				k += ((3 * j) + 1) % 4;
			} else {
				k += (7 * j) % 4;
			}
			char oldA = A;
			char oldC = C;
			A = D;
			D = C;
			C += B;
			B = rotl8((func(oldA, oldC, j % 4) + get(k, 'B')) ^ VALS_B[j], SHIFT_B[j]);
		}
	}
	arr = NULL;
	// return in big endian
	return (((int)A << 24) & 0xff000000) + (((int)B << 16) & 0x00ff0000) + (((int)C << 8) & 0x0000ff00) + (((int)D) & 0x000000ff);
}
char* Hash::generateSHA2_256(char* input, long long size) {
	// Generate a new array for the "padding" of the SHA-2 algorithm
	long long arrsize = ((64 - ((size + 9) % 64)) % 64) + 9;
	char* arr = (char*)calloc(arrsize, sizeof(char));
	arr[0] = 0x80;
	Util::writeBigEndianLong(arr, arrsize - 8, size << 3);
	unsigned int h0 = 0x6a09e667;
	unsigned int h1 = 0xbb67ae85;
	unsigned int h2 = 0x3c6ef372;
	unsigned int h3 = 0xa54ff53a;
	unsigned int h4 = 0x510e527f;
	unsigned int h5 = 0x9b05688c;
	unsigned int h6 = 0x1f83d9ab;
	unsigned int h7 = 0x5be0cd19;
	long long iterations = (size + arrsize) / 64;
	for (long long k = 0; k < iterations; k++) {
		unsigned int w[64];
		unsigned int s0, s1, temp1, temp2, ch, maj;
		for (int i = 0; i < 16; i++) {
			w[i] = 0;
			for (int j = 0; j < 4; j++) {
				w[i] <<= 8;
				w[i] += (unsigned int)(getSHA2_256((k << 6) + (i << 2) + j, input, arr, size) & 0x000000ff);
			}
		}
		for (int i = 16; i < 64; i++) {
			s0 = rotr32u(w[i-15], 7) ^ rotr32u(w[i-15], 18) ^ (w[i-15] >> 3);
			s1 = rotr32u(w[i-2], 17) ^ rotr32u(w[i-2], 19) ^ (w[i-2] >> 10);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}
		unsigned int a = h0;
		unsigned int b = h1;
		unsigned int c = h2;
		unsigned int d = h3;
		unsigned int e = h4;
		unsigned int f = h5;
		unsigned int g = h6;
		unsigned int h = h7;
		for (int i = 0; i < 64; i++) {
			s1 = rotr32u(e, 6) ^ rotr32u(e, 11) ^ rotr32u(e, 25);
			ch = (e & f) ^ ((~e) & g);
			temp1 = h + s1 + ch + VALS_SHA2_256[i] + w[i];
			s0 = rotr32u(a, 2) ^ rotr32u(a, 13) ^ rotr32u(a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}
	free(arr);
	arr = (char*)malloc(32 * sizeof(char));
	Util::writeBigEndianInt(arr, 0, h0);
	Util::writeBigEndianInt(arr, 4, h1);
	Util::writeBigEndianInt(arr, 8, h2);
	Util::writeBigEndianInt(arr, 12, h3);
	Util::writeBigEndianInt(arr, 16, h4);
	Util::writeBigEndianInt(arr, 20, h5);
	Util::writeBigEndianInt(arr, 24, h6);
	Util::writeBigEndianInt(arr, 28, h7);
	return arr;
}