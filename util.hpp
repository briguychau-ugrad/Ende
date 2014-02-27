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
 * util.hpp
 *
 * Header file for utility functions
 */
#ifndef _UTIL_HPP
#define _UTIL_HPP
namespace Util {
	void writeBigEndianInt(char* arr, long long index, int value);
	void writeLittleEndianInt(char* arr, long long index, int value);
	void writeBigEndianLong(char* arr, long long index, long long value);
	void writeLittleEndianLong(char* arr, long long index, long long value);
	int readBigEndianInt(char* arr, long long index);
	int readLittleEndianInt(char* arr, long long index);
	long long readBigEndianLong(char* arr, long long index);
	long long readLittleEndianLong(char* arr, long long index);
	char* generateSaltedPassword(char* pw, int time);
}
#endif
