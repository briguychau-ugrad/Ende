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
#include "prng.hpp"
#include <ctime>
// VALS[0] = A, VALS[1] = C, VALS[2] = M, VALS[3] = mod, VALS[4] = initial advances
const long long Lcg1::VALS[5] = {135317LL, 610279LL, 1LL<<60, 28, 17LL};
Lcg1::Lcg1() {
	seed(std::time(0));
}
Lcg1::Lcg1(long long s) {
	seed(s);
}
void Lcg1::seed(long long s) {
	value = s;
	int x = (int)VALS[4];
	while (x--) {
		get();
	}
}
int Lcg1::get() {
	value *= VALS[0];
	value += VALS[1];
	value %= VALS[2];
	return (int)(value >> VALS[3]);
}
const long long Lcg2::VALS[5] = {292069LL, 1429LL, 1LL<<48, 16, 157LL};
Lcg2::Lcg2() {
	seed(std::time(0));
}
Lcg2::Lcg2(long long s) {
	seed(s);
}
void Lcg2::seed(long long s) {
	value = s;
	int x = (int)VALS[4];
	while (x--) {
		get();
	}
}
int Lcg2::get() {
	value *= VALS[0];
	value += VALS[1];
	value %= VALS[2];
	return (int)(value >> VALS[3]);
}
MersenneTwister::MersenneTwister() {
	index = -1;
	seed(std::time(0));
}
MersenneTwister::MersenneTwister(int s) {
	index = -1;
	seed(s);
}
void MersenneTwister::generate() {
	for (index = 0; index < 624; index++) {
		unsigned int y = (arr[index] & 0x80000000) + (arr[(index + 1) % 624] & 0x7fffffff);
		arr[index] = arr[(index + 397) % 624] ^ (y >> 1);
		if (y % 2 != 0) {
			arr[index] ^= 0x9908b0df;
		}
	}
	index = 0;
}
void MersenneTwister::seed(int s) {
	index = 0;
	arr[index++] = (unsigned int)s;
	for (; index < 624; index++) {
		arr[index] = (0x6c078965 * (arr[index-1] ^ (arr[index-1] >> 30))) + index;
	}
}
int MersenneTwister::get() {
	if (index == -1)
		seed(std::time(0));
	if (index == 624)
		generate();
	unsigned int y = arr[index++];
	y ^= (y >> 11);
	y ^= ((y << 7) & 0x9d2c5680);
	y ^= ((y << 15) & 0xefc60000);
	y ^= (y >> 18);
	return (int)y;
}