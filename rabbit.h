#include "binary_convert.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
using namespace std;
unsigned long long maxsize = 4294967296ll;
// Dinh nghia du lieu cac dau vao : 
unsigned int key[8];
unsigned int iv[2];
//Biến state và counter được khởi tạo như sau:
unsigned int X[8]; //state
unsigned int C[8],old_C[8]; //counter

unsigned int A[8]; // Tao gia tri a
unsigned int carry;

// 
unsigned int rotate_left(unsigned int v, unsigned int k) {
	return (k%32 == 0) ? v : ((v << k) | (v >> (32 - k)));
}
void reset(){
	for(int i=0;i<8;i++){
		X[i] = C[i] = 0;
	}
	// Cac gia tri A duoc dinh nghia nhu sau 
	A[0] = A[3] = A[6] = 0x4D34D34D;
	A[1] = A[4] = A[7] = 0xD34D34D3;
	A[2] = A[5] = 0x34D34D34;
}
// Tao ham counter system
void counter_system(){
	long long temp;
	long long b=0;
	// Luu gia tri counter cu 
	for(int i=0;i<8;i++) old_C[i]=C[i];

	// Tao moi gia tri counter 
	temp = (C[0] % maxsize) + (A[0] % maxsize) + carry;
    C[0] = (unsigned int) (temp % maxsize);

	for(int i=1;i<8;i++) {
		temp = (C[i] % maxsize) + (A[i] % maxsize) + (old_C[i-1]>C[i-1]);
		C[i] = (unsigned int) (temp % maxsize);
	}
	carry = (old_C[7]>C[7]);
}

// Tính toán trạng thái bên trong tiếp theo
void next_state(){
	// Ham luu gia tri counter cu
	counter_system();
	unsigned int g[8];
	long long temp;
	// Tao ham g-functions
	for(int i=0;i<8;i++) {
		temp = (X[i] + C[i]) % maxsize;
		temp = temp*temp;
		g[i] = (unsigned int)( ((temp) ^ (temp >> 32))% maxsize);
	}
	// Tao gia tri state moi
	for(int i=0;i<8;i++){
		if(i&1)
			X[i] = g[i] + rotate_left(g[(i+7)%8],8) + g[(i+6)%8];
		else
			X[i] = g[i] + rotate_left(g[(i+7)%8],16) + rotate_left(g[(i+6)%8],16);
	}
}
// Ham IV Setup : 
void iv_setup(){
	// Đặt tên internal state sau bước 1 là master state, 
	//và đưa copy của master state vào để tiến hành thiết lập IV
	C[0]^=iv[0];
	C[2]^=iv[1];
	C[4]^=iv[0];
	C[6]^=iv[1];
	C[1]^=( ((iv[1]>>16)<<16) | ((iv[0]>>16)) );
	C[3]^=( (iv[1]<<16) | ((iv[0]<<16)>>16) );
	C[5]^=( ((iv[1]>>16)<<16) | ((iv[0]>>16)) );
	C[7]^=( (iv[1]<<16) | ((iv[0]<<16)>>16) );
	//Lap lai state 4 lan
	for(int i=0;i<4;i++){
		next_state();
	}
}

//Ham thuc hien chuc nang key_setup : 
void key_setup(){
	for(int i=0;i<8;i++){
		if(i%2){
			X[i] = (key[(i+5)%8]<<16) | key[(i+4)%8];
			C[i] = (key[i]<<16) | (key[(i+1)%8]);
		}
		else{
			X[i] = (key[(i+1)%8]<<16) | key[i];
			C[i] = (key[(i+4)%8]<<16) | (key[(i+5)%8]);
		}
	}
    carry=0;
	//Iteration 4 lần tương ứng với next – state function ở bước 3
	for(int i=0;i<4;i++){
		next_state();
	}
	// Bien counter duoc khoi tao lai lan nua 
	for (int i = 0; i < 8; i++)
        C[(i + 4) %8] ^= X[i];

}

// Tao ham encrypt 
void encrypt(vector <unsigned int> plain_text,bool do_iv_setup=true){
	//Reset va setup key 
	reset();
	key_setup();
	if(do_iv_setup)
		iv_setup();
	vector <unsigned int> cipher_text;
	for(int i=0;i<plain_text.size();){
		next_state();
		//Các bit được trích xuất được XOR với bản rõ/bản mã để mã hóa/giải mã
		for(int j=0;j<8 && i<plain_text.size();j+=2,i++){
			unsigned int temp = plain_text[i] ^ X[j] ^ (X[(j+5)%8]>>16) ^ (X[(j+3)%8]<<16);
			cipher_text.push_back(temp);
			convert(temp);
		}
	}
	//printf("Cipher text in hex:\n");
	for(int i=0;i<cipher_text.size();i++){
		//printf("%02X %02X %02X %02X ",(cipher_text[i]&0x000000FF),(cipher_text[i]&0x0000FF00)>>8,
		//(cipher_text[i]&0x00FF0000)>>16,(cipher_text[i]&0xFF000000)>>24);
	}
	//cout<<endl;
}