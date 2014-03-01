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
 * sha2.hpp
 *
 * Header file for SHA-2 functions
 */
#ifndef _SHA2_HPP
#define _SHA2_HPP
class Sha2 {
private:
	static const unsigned int VALS_SHA_256[64];
	static const unsigned long long VALS_SHA_512[80];
	static char getCharFromTwoFiles(long long index, char* first, char* second, long long firstsize);
	static unsigned int rotr32u(unsigned int val, int n);
	static unsigned long long rotr64u(unsigned long long val, int n);
public:
	static char* sha256(char* input, long long size);
	static char* sha512(char* input, long long size);
};
#endif
