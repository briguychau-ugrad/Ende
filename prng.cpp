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
 * prng.cpp
 *
 * PRNG functions
 */
#include "prng.h"
// arr[0] = A, arr[1] = C, arr[2] = M, arr[3] = mod, arr[4] = initial advances
const long long Prng::PRNG_1_VALS[5] = {135317LL, 610279LL, 1LL<<60, 28, 17LL};
const long long Prng::PRNG_2_VALS[5] = {292069LL, 1429LL, 1LL<<48, 16, 157LL};
long long Prng::prng1Value;
long long Prng::prng2Value;
int Prng::mt[624];
int Prng::mtIndex;
void Prng::initPrng1(long long seed) {
	prng1Value = seed;
	int x = (int)PRNG_1_VALS[4];
	while (x--) {
		getPrng1();
	}
}
void Prng::initPrng2(long long seed) {
	prng2Value = seed;
	int x = (int)PRNG_2_VALS[4];
	while (x--) {
		getPrng2();
	}
}
void Prng::initMT(int seed) {
	mtIndex = 0;
	mt[0] = seed;
	for (int i = 1; i < 624; i++) {
		mt[i] = 0x6c078965 * (mt[i-1] ^ (mt[i-1] >> 30)) + i;
	}
}
int Prng::getPrng1() {
	prng1Value *= PRNG_1_VALS[0];
	prng1Value += PRNG_1_VALS[1];
	prng1Value %= PRNG_1_VALS[2];
	return (int)(prng1Value >> PRNG_1_VALS[3]);
}
int Prng::getPrng2() {
	prng2Value *= PRNG_2_VALS[0];
	prng2Value += PRNG_2_VALS[1];
	prng2Value %= PRNG_2_VALS[2];
	return (int)(prng2Value >> PRNG_2_VALS[3]);
}
int Prng::getMT() {
	if (mtIndex == 0)
		mtGenerate();
	int y = mt[index];
	y ^= (y >> 11);
	y ^= ((y << 7) & 0x9d2c5680);
	y ^= ((y << 15) & 0xefc60000);
	y ^= (y >> 18);
	index = (index + 1) % 624;
	return y;
}
void Prng::mtGenerate() {
	for (int i = 0; i < 624; i++) {
		int y = mt[i] & 0x80000000 + (mt[(i + 1) % 624] & 0x7fffffff);
		mt[i] = mt[(i + 397) % 624] ^ (y >> 1);
		if (y % 2 != 0) {
			mt[i] ^= 0x9908b0df;
		}
	}
}