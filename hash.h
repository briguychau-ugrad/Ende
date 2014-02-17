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
 * hash.h
 *
 * Header file for hash functions
 */
#ifndef _HASH_H
#define _HASH_H
class Hash {
private:
	static const char VALS_A[16];
	static const char VALS_B[16];
	static const int SHIFT_A[16];
	static const int SHIFT_B[16];
	static char* arr;
	static long hsize;
	static char get(int index, char f);
	static char shl(char val, char n);
	static char func(char a, char c, int x);
public:
	static int generateHashA(char* input, long size);
	static int generateHashB(char* input, long size);
};
 #endif
