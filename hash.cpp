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
#include "hash.hpp"
#include "util.hpp"
#include <cstdlib>
const char Hash::VALS_A[16] = {(char)0x34, (char)0xee, (char)0x4e, (char)0xa7,
			       (char)0x03, (char)0x44, (char)0x14, (char)0x07,
			       (char)0xdc, (char)0x97, (char)0x3b, (char)0xed,
			       (char)0x8e, (char)0x8b, (char)0xb0, (char)0xea };
const char Hash::VALS_B[16] = {(char)0x2a, (char)0x04, (char)0x14, (char)0x61,
			       (char)0xc4, (char)0xe9, (char)0xf4, (char)0x3e,
			       (char)0xbb, (char)0xa2, (char)0xb3, (char)0xbc,
			       (char)0xf8, (char)0x1a, (char)0x3c, (char)0xe4 };
const int Hash::SHIFT_A[16] = {3, 6, 4, 1,
			       7, 2, 0, 5,
			       6, 6, 3, 0,
			       7, 2, 5, 0 };
const int Hash::SHIFT_B[16] = {5, 3, 0, 3,
			       7, 2, 6, 4,
			       4, 1, 2, 6,
			       1, 5, 1, 3 };
char Hash::get(int index, char f, char* arr, long long arrsize) {
	if (index >= arrsize) {
		if (index - arrsize > 3) throw -1;
		if (f == 'A')
			return index - arrsize;
		if (f == 'B') {
			switch (index - arrsize) {
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
char Hash::rotl8(char val, int n) {
	char ls = n;
	char rs = 8 - n;
	unsigned char lm = 0xff << ls;
	unsigned char rm = 0xff >> rs;
	return (char)((((unsigned char)(val) << ls) & lm) + (((unsigned char)(val) >> rs) & rm));
}
char Hash::func(char a, char c, int x) {
	switch (x) {
		case 0:
			return a ^ c;
		case 1:
			return rotl8(a, 1) + rotl8(c, 7);
		case 2:
			return rotl8(a, 3) ^ rotl8(c, 6);
		case 3:
			return a + c;
	}
	throw -1;
}
int Hash::generateHashA(char* input, long long size) {
	char A = 0x62;
	char B = 0x49;
	char C = 0xfc;
	char D = 0x3f;
	// Get number of iterations
	int iterations = (size / 4) + 1;
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
			A = rotl8((B + D) + get(k, 'A', input, size) + VALS_A[j], SHIFT_A[j]);
			B = C ^ oldA;
			C = D;
			D = oldA;
		}
	}
	// return in big endian
	return (((int)A << 24) & 0xff000000) + (((int)B << 16) & 0x00ff0000) + (((int)C << 8) & 0x0000ff00) + (((int)D) & 0x000000ff);
}
int Hash::generateHashB(char* input, long long size) {
	char A = 0x84;
	char B = 0x5d;
	char C = 0x6f;
	char D = 0xff;
	// Get number of iterations
	int iterations = ((size - 1) / 4) + 1;
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
			B = rotl8((func(oldA, oldC, j % 4) + get(k, 'B', input, size)) ^ VALS_B[j], SHIFT_B[j]);
		}
	}
	// return in big endian
	return (((int)A << 24) & 0xff000000) + (((int)B << 16) & 0x00ff0000) + (((int)C << 8) & 0x0000ff00) + (((int)D) & 0x000000ff);
}
