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
