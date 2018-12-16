#include "x509.h"

X509::X509(string data)
{
    int length = 0;
    parseBase64(data, length);
    cout<<"Length:"<<length<<endl;
    parseCertificate(0, length);
    printResult();
}

// base 64解码
void X509::parseBase64(string dataToString, int &length)
{
    // 填充为整数byte
    if (dataToString.length() % 4 != 0)
    {
        for (int i = 0; i < 4 - dataToString.length() % 4; i++)
        {
            dataToString += "0";
        }
    }
    length = (dataToString.length() / 4) * 3;
    // 按照byte进行分割
    data = new byte[length];
    memset(data, length, 0);
    int currentPos = 0;
    for (int i = 0; i < dataToString.length(); i += 4)
    {
        byte base64Code[4];
        // 通过索引获得位置
        for (int j = 0; j < 4; j++)
        {
            base64Code[j] = dictionary.find(dataToString[i + j]);
        }

        // base64 -> byte
        data[currentPos++] = ((base64Code[0] & 0x3f)<<2) | ((base64Code[1] & 0x30) >> 4);
        data[currentPos++] = ((base64Code[1] & 0x0f)<<4) | ((base64Code[2] & 0x3c) >> 2);
        data[currentPos++] = ((base64Code[2] & 0x03)<<6) | (base64Code[3] & 0x3f);
    }
}

void X509::parseCertificate(int begin, int end)
{
    int pointer = begin;
    while (pointer < end)
    {
        // 类型
        int type = data[pointer++];
        // 获得长度
        int length = 0;
        if (data[pointer] & 0x80)
        {
            int lenOfLength = data[pointer++] & 0x7f;
            while (lenOfLength--)
            {
                length <<= 8;
                length += data[pointer++];
            }
        }
        else
        {
            length = data[pointer++] & 0x7f;
        }

        if (length < 0 || pointer + length > end)
        {
            break;
        }

        string tag = "";
        vector<byte> vec;
        
        // 对各种类型的type进行判断和处理
        if (type == 0)
        {
            for (int i = begin + 1; i < end; i++)
            {
                vec.push_back(data[i]);
            }
            DER der("Remained", end - begin - 1, type, vec);
            dataGroup.push_back(der);
        }
        else if (type == 1)
        {
            DER der(data[pointer] == 0 ? "False" : "True", length, type);
            dataGroup.push_back(der);
        }
        else if (type == 6)
        {
            int index = 0;
            int byteData = 0;
            for (int i = 0; i < length; i++)
            {
                byteData <<= 7;
                byteData += data[pointer + i] & 0x7f;
                if ((data[pointer + i] & 0x80) == 0)
                {
                    // 第一次进行拆分
                    if (i == 0)
                    {
                        int firstNum = min(byteData / 40, 2);
                        tag += to_string(firstNum) + "." + to_string(byteData - 40 * firstNum) + ".";
                        index++;
                    }
                    else
                    {
                        tag += to_string(byteData) + ".";
                    }
                    byteData = 0;
                    index++;
                }
            }
            DER der(tag.substr(0, tag.length() - 1), length, type);
            dataGroup.push_back(der);
        }
        else if (type == 2 || type == 3 || type == 128)
        {
            if (type == 3)
                length--;
            for (int i = 0; i < length; i++)
            {
                if (type == 3)
                    vec.push_back(data[pointer + i + 1]);
                else
                    vec.push_back(data[pointer + i]);
            }
            DER der(tag, length, type, vec);
            dataGroup.push_back(der);
        }
        else if(type == 23){
            tag = "ValidTime";
            for(int i = 0; i < length; i++){
                vec.push_back(data[pointer + i]);
            }
            DER der(tag, length, type, vec);
            dataGroup.push_back(der);
        }
        else if (type == 4 || type == 48 || type == 49)
        {
            parseCertificate(pointer, pointer + length);
        }
        else if (type == 160 || type == 163)
        {
            tag = (type == 160) ? "Version" : "Extension";
            DER der(tag, length, type);
            dataGroup.push_back(der);
            parseCertificate(pointer, pointer + length);
        }
        else if (type == 12 || type == 19 || type == 22 || type == 130 || type == 134)
        {
            for (int i = 0; i < length; i++)
            {
                tag += (char)data[pointer + i];
            }
            DER der(tag, length, type);
            dataGroup.push_back(der);
        }
        else
        {
            if (type != 5)
            {
                for (int i = 0; i < length; i++)
                {
                    vec.push_back(data[pointer + i - 1]);
                }
                DER der("", length, type, vec);
                dataGroup.push_back(der);
            }
        }
        pointer += length;
    }
}

void X509::printResult()
{
    int pointer = 0;
    while(pointer < dataGroup.size())
    {
        // 获得当前的标签
        string currentTag = dataGroup[pointer].tag;
        if (currentTag == "Version")
        {
            // 判断下一个
            if (dataGroup[++pointer].type == 2)
            {
                cout<<endl;
                cout<<"Version: "<<((int)dataGroup[pointer].data[0] + 1)<<endl;
                DER newder = dataGroup[++pointer];
                cout<<"Seqence: ";
                Hex(newder.data, newder.length);
            }
            else
            {
                pointer--;
            }
        }
        else if (currentTag == "ValidTime")
        {
            DER der1 = dataGroup[pointer];
            DER der2 = dataGroup[++pointer];
            // 暴力算法
            cout<<endl;
            cout<<"Valid From: 20"<<(char)der1.data[0]<<(char)der1.data[1]<<"-"<<(char)der1.data[2]<<(char)der1.data[3]<<"-";
            cout<<(char)der1.data[4]<<(char)der1.data[5]<<" "<<(char)der1.data[6]<<(char)der1.data[7]<<":";
            cout<<(char)der1.data[8]<<(char)der1.data[9]<<":"<<(char)der1.data[10]<<(char)der1.data[11]<<endl;
            cout<<"        To: 20"<<(char)der2.data[0]<<(char)der2.data[1]<<"-"<<(char)der2.data[2]<<(char)der2.data[3]<<"-";
            cout<<(char)der2.data[4]<<(char)der2.data[5]<<" "<<(char)der2.data[6]<<(char)der2.data[7]<<":";
            cout<<(char)der2.data[8]<<(char)der2.data[9]<<":"<<(char)der2.data[10]<<(char)der2.data[11]<<endl;
        }
        else if (currentTag == "Remained")
        {
            cout<<endl;
            cout<<"Public Key: ";
            Hex(dataGroup[pointer].data, dataGroup[pointer].length);
        }
        // 16进制输出
        else if (hexMap.find(currentTag) != hexMap.end())
        {
            cout<<hexMap[currentTag]<<": ";
            DER der = dataGroup[++pointer];
            if (!der.data.empty())
            {
                Hex(der.data, der.length);
            }
            else
            {
                cout<<"NaN"<<endl;
                pointer--;
            }
        }
        // string类型
        else if (string_map.find(currentTag) != string_map.end())
        {
            cout<<endl;
            cout<<string_map[currentTag]<<endl;
        }
        // OID
        else if (OID_map.find(currentTag) != OID_map.end())
        {
            cout<<endl;
            cout<<OID_map[currentTag];
            cout<<dataGroup[++pointer].tag<<endl;
        }
        // 加密算法
        else if (algorithmMap.find(currentTag) != algorithmMap.end())
        {
            cout<<endl;
            cout<<"Algorithm: "<<algorithmMap[currentTag];
            DER newder = dataGroup[++pointer];
            if (newder.type == 3)
            {
                cout<<endl;
                cout<<"Public Key:";
                Hex(newder.data, newder.length);
            }
            else
            {
                // cout<<"NaN"<<endl;
                pointer--;
            }
        }
        else if (SubjectAlternativeName.find(currentTag) != SubjectAlternativeName.end())
        {
            // 存储名字
            vector<string> nameVec;
            DER der = dataGroup[++pointer];
            while (der.type == 130)
            {
                nameVec.push_back(der.tag);
                der = dataGroup[++pointer];
            }
            pointer--;
            cout<<endl;
            cout<<"Subject Alternative Name: "<<endl;
            for(int pointer = 0; pointer < nameVec.size(); pointer++){
                cout<<nameVec[pointer];
                if(pointer < nameVec.size() - 1) cout<<" | ";
            }
            cout<<endl;
        }
        pointer++;
    }
}

void X509::Hex(vector<byte> data, int length)
{
    cout<<hex;
    for (int i = 0; i < length; i++)
    {
        // 高低部分分别输出
        int heighPart = data[i] >> 4;
        heighPart &= 0x0f;
        cout<<heighPart<<(data[i] & 0x0f);
        if (i != 0 && i % 40 == 0)
            cout<<endl;
    }
    cout<<endl;
    cout<<dec;
}