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
 * sha2.cpp
 *
 * SHA-2 functions
 */
#include "sha2.hpp"
#include "util.hpp"
#include <cstdlib>
const unsigned int Sha2::VALS_SHA_256[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
					     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
					     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
					     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
					     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
					     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
const unsigned long long Sha2::VALS_SHA_512[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
						   0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
						   0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
						   0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
						   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
						   0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
						   0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
						   0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
						   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
						   0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
						   0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
						   0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
						   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
						   0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
						   0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
						   0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };
char Sha2::getCharFromTwoFiles(long long index, char* first, char* second, long long firstsize) {
	if (index < firstsize)
		return first[index];
	else
		return second[index-firstsize];
}
unsigned int Sha2::rotr32u(unsigned int val, int n) {
	int ls = 32 - n;
	int rs = n;
	unsigned int lm = 0xffffffff << ls;
	unsigned int rm = 0xffffffff >> rs;
	return ((val << ls) & lm) + ((val >> rs) & rm);
}
unsigned long long Sha2::rotr64u(unsigned long long val, int n) {
	int ls = 64 - n;
	int rs = n;
	unsigned long long lm = 0xffffffffffffffff << ls;
	unsigned long long rm = 0xffffffffffffffff >> rs;
	return ((val << ls) & lm) + ((val >> rs) & rm);
}
char* Sha2::sha256(char* input, long long size) {
	// Generate a new array for the "padding" of the SHA-2 algorithm
	long long arrsize = ((64 - ((size + 9) % 64)) % 64) + 9;
	char* arr = (char*)std::calloc(arrsize, sizeof(char));
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
				w[i] += (unsigned int)(getCharFromTwoFiles((k << 6) + (i << 2) + j, input, arr, size) & 0x000000ff);
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
			temp1 = h + s1 + ch + VALS_SHA_256[i] + w[i];
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
	std::free(arr);
	arr = (char*)std::malloc(32 * sizeof(char));
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
char* Sha2::sha512(char* input, long long size) {
	// Generate a new array for the "padding" of the SHA-2 algorithm
	long long arrsize = ((128 - ((size + 17) % 128)) % 128) + 17;
	char* arr = (char*)std::calloc(arrsize, sizeof(char));
	arr[0] = 0x80;
	Util::writeBigEndianLong(arr, arrsize - 8, size << 3);
	arr[arrsize-9] = (char)((size >> 61) & 0x00000007);
	unsigned long long h0 = 0x6a09e667f3bcc908ull;
	unsigned long long h1 = 0xbb67ae8584caa73bull;
	unsigned long long h2 = 0x3c6ef372fe94f82bull;
	unsigned long long h3 = 0xa54ff53a5f1d36f1ull;
	unsigned long long h4 = 0x510e527fade682d1ull;
	unsigned long long h5 = 0x9b05688c2b3e6c1full;
	unsigned long long h6 = 0x1f83d9abfb41bd6bull;
	unsigned long long h7 = 0x5be0cd19137e2179ull;
	long long iterations = (size + arrsize) / 128;
	for (long long k = 0; k < iterations; k++) {
		unsigned long long w[80];
		unsigned long long s0, s1, temp1, temp2, ch, maj;
		for (int i = 0; i < 16; i++) {
			w[i] = 0;
			for (int j = 0; j < 8; j++) {
				w[i] <<= 8;
				w[i] += (unsigned long long)(getCharFromTwoFiles((k << 7) + (i << 3) + j, input, arr, size) & 0x00000000000000ffull);
			}
		}
		for (int i = 16; i < 80; i++) {
			s0 = rotr64u(w[i-15], 1) ^ rotr64u(w[i-15], 8) ^ (w[i-15] >> 7);
			s1 = rotr64u(w[i-2], 19) ^ rotr64u(w[i-2], 61) ^ (w[i-2] >> 6);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}
		unsigned long long a = h0;
		unsigned long long b = h1;
		unsigned long long c = h2;
		unsigned long long d = h3;
		unsigned long long e = h4;
		unsigned long long f = h5;
		unsigned long long g = h6;
		unsigned long long h = h7;
		for (int i = 0; i < 80; i++) {
			s1 = rotr64u(e, 14) ^ rotr64u(e, 18) ^ rotr64u(e, 41);
			ch = (e & f) ^ ((~e) & g);
			temp1 = h + s1 + ch + VALS_SHA_512[i] + w[i];
			s0 = rotr64u(a, 28) ^ rotr64u(a, 34) ^ rotr64u(a, 39);
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
	std::free(arr);
	arr = (char*)std::malloc(64 * sizeof(char));
	Util::writeBigEndianLong(arr, 0, h0);
	Util::writeBigEndianLong(arr, 8, h1);
	Util::writeBigEndianLong(arr, 16, h2);
	Util::writeBigEndianLong(arr, 24, h3);
	Util::writeBigEndianLong(arr, 32, h4);
	Util::writeBigEndianLong(arr, 40, h5);
	Util::writeBigEndianLong(arr, 48, h6);
	Util::writeBigEndianLong(arr, 56, h7);
	return arr;
}
