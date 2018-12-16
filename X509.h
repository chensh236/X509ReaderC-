#pragma once
#include <iostream>
#include <vector>
#include "staticNumbers.h"
using namespace std;
typedef unsigned char byte;

typedef struct DER
{
    string tag;
    int length;
    int type;
    vector<byte> data;
    DER(string _tag, int _length, int _type)
    {
        tag = _tag;
        length = _length;
        type = _type;
    }
    DER(string _tag, int _length, int _type, vector<byte> vec)
    {
        tag = _tag;
        length = _length;
        type = _type;
        data = vec;
    }
} DER;

class X509
{
public:
	X509(string);
	~X509(){
		delete[] data;
	}
private:
	void parseBase64(string, int &);
	void printResult();
	void Hex(vector<byte>, int);
	void parseCertificate(int, int);

	byte* data;
	vector<DER> dataGroup;
};