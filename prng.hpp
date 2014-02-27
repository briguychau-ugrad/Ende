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
 * prng.hpp
 *
 * Header file for PRNG functions
 */
#ifndef _PRNG_HPP
#define _PRNG_HPP
class Lcg1 {
private:
	static const long long VALS[5];
	long long value;
public:
	Lcg1();
	Lcg1(long long s);
	void seed(long long s);
	int get();
};
class Lcg2 {
private:
	static const long long VALS[5];
	long long value;
public:
	Lcg2();
	Lcg2(long long s);
	void seed(long long s);
	int get();
};
class MersenneTwister {
private:
	unsigned int arr[624];
	int index;
	void generate();
public:
	MersenneTwister();
	MersenneTwister(int s);
	void seed(int s);
	int get();
};
#endif