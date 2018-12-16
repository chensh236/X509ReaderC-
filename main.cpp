#include <cstring>
#include <iostream>
#include <fstream>
#include "x509.h"
#define BUFFSIZE 1024
using namespace std;

int main(){
    string fileName;
    cout<<"Please input the filename:(default: ../test/apple.com.cer)"<<endl;
    cin>>fileName;
    ifstream ifs(fileName);
    if (!ifs.is_open())
    {
        cout << "Fail to open the file"<<endl;
        return 0;
    }
    char buffer[BUFFSIZE];
    string content = "";
    while (!ifs.eof())
    {
        ifs.getline(buffer, BUFFSIZE);
        string bufStr = string(buffer);
        // 判断是否结束
        if (bufStr.find("END CERTIFICATE") != -1)
        {
            X509 x(content);
        }
        else if(string(buffer).find("BEGIN CERTIFICATE") == -1)
        {
            content += bufStr;
        }
    }
    return 0;
}
