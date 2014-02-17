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
 * prng.h
 *
 * Header file for PRNG functions
 */
#ifndef _PRNG_H
#define _PRNG_H
class Prng {
private:
	static const long long PRNG_1_VALS[5];
	static const long long PRNG_2_VALS[5];
	static long long prng1Value;
	static long long prng2Value;
public:
	static void initPrng1(long long seed);
	static void initPrng2(long long seed);
	static int getPrng1();
	static int getPrng2();
};
#endif
