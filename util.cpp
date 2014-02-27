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
 * util.cpp
 *
 * Utility functions
 */
#include "hash.hpp"
#include "prng.hpp"
#include "util.hpp"
#include <cstdlib>
namespace Util {
	void writeBigEndianInt(char* arr, long long index, int value) {
		arr[index++] = (char)((value >> 24) & 0x000000ff);
		arr[index++] = (char)((value >> 16) & 0x000000ff);
		arr[index++] = (char)((value >> 8) & 0x000000ff);
		arr[index] = (char)(value & 0x000000ff);
	}
	void writeLittleEndianInt(char* arr, long long index, int value) {
		arr[index++] = (char)(value & 0x000000ff);
		arr[index++] = (char)((value >> 8) & 0x000000ff);
		arr[index++] = (char)((value >> 16) & 0x000000ff);
		arr[index] = (char)((value >> 24) & 0x000000ff);
	}
	void writeBigEndianLong(char* arr, long long index, long long value) {
		arr[index++] = (char)((value >> 56) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 48) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 40) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 32) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 24) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 16) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 8) & 0x00000000000000ffLL);
		arr[index] = (char)(value & 0x00000000000000ffLL);
	}
	void writeLittleEndianLong(char* arr, long long index, long long value) {
		arr[index++] = (char)(value & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 8) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 16) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 24) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 32) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 40) & 0x00000000000000ffLL);
		arr[index++] = (char)((value >> 48) & 0x00000000000000ffLL);
		arr[index] = (char)((value >> 56) & 0x00000000000000ffLL);
	}
	int readBigEndianInt(char* arr, long long index) {
		return (((int)arr[index] << 24) & 0xff000000)
		     | (((int)arr[index+1] << 16) & 0x00ff0000)
		     | (((int)arr[index+2] << 8) & 0x0000ff00)
		     | ((int)arr[index+3] & 0x000000ff);
	}
	int readLittleEndianInt(char* arr, long long index) {
		return ((int)arr[index] & 0x000000ff)
		     | (((int)arr[index+1] << 8) & 0x0000ff00)
		     | (((int)arr[index+2] << 16) & 0x00ff0000)
		     | (((int)arr[index+3] << 24) & 0xff000000);
	}
	long long readBigEndianLong(char* arr, long long index) {
		return (((long long)arr[index] << 56) & 0xff00000000000000LL)
		     | (((long long)arr[index+1] << 48) & 0x00ff000000000000LL)
		     | (((long long)arr[index+2] << 40) & 0x0000ff0000000000LL)
		     | (((long long)arr[index+3] << 32) & 0x000000ff00000000LL)
		     | (((long long)arr[index+4] << 24) & 0x00000000ff000000LL)
		     | (((long long)arr[index+5] << 16) & 0x0000000000ff0000LL)
		     | (((long long)arr[index+6] << 8) & 0x000000000000ff00LL)
		     | ((long long)arr[index+7] & 0x00000000000000ffLL);
	}
	long long readLittleEndianLong(char* arr, long long index) {
		return ((long long)arr[index] & 0x00000000000000ffLL)
		     | (((long long)arr[index+1] << 8) & 0x000000000000ff00LL)
		     | (((long long)arr[index+2] << 16) & 0x0000000000ff0000LL)
		     | (((long long)arr[index+3] << 24) & 0x00000000ff000000LL)
		     | (((long long)arr[index+4] << 32) & 0x000000ff00000000LL)
		     | (((long long)arr[index+5] << 40) & 0x0000ff0000000000LL)
		     | (((long long)arr[index+6] << 48) & 0x00ff000000000000LL)
		     | (((long long)arr[index+7] << 56) & 0xff00000000000000LL);
	}
	char* generateSaltedPassword(char* pw, int time) {
		long long l;
		for (l = 0; pw[l] != '\0'; l++) {
		}
		int mt_seed = Hash::generateHashA(pw, l) ^ Hash::generateHashB(pw, l);
		Prng::initMT(mt_seed);
		for (int i = 0; i < time % 128; i++) {
			Prng::getMT();
		}
		char* arr = (char*)std::malloc((l + 17) * sizeof(char));
		for (int i = 0; i < l; i++) {
			arr[i] = pw[i];
		}
		writeBigEndianInt(arr, l, Prng::getMT());
		writeBigEndianInt(arr, l + 4, Prng::getMT());
		writeBigEndianInt(arr, l + 8, Prng::getMT());
		writeBigEndianInt(arr, l + 12, Prng::getMT());
		arr[l + 16] = 0;
		return arr;
	}
}
