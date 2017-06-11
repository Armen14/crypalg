#include <QtCore/QCoreApplication>
#include <iostream>
#include <qdebug.h>
#include <bitset>

#define C1   0x1010101
#define C2   0x1010104

using namespace std;

quint64 main_step(quint64 N, quint32 X);
quint64 Z_32(quint64 N);
quint64 R_32(quint64 N);
quint64 Z_16(quint64 N);
quint64* replace_encrypt(quint64* data, int size_data);
quint64* replace_decrypt(quint64* data, int size_data);
quint64* new_array_64(int size);
quint64* gamma(quint64* data, int size,quint64 S);
quint64* gamma_os(quint64* data, int size, quint64 S);
quint64* imito(quint64 *data, int size);


typedef bitset<4> bit4;
typedef bitset<32> bit32;
typedef bitset<64> bit64;

bit32 key[8];
quint8 table[16][8];

int main() {

    table[0][0] = 4;    table[0][1] = 14;   table[0][2] = 5;    table[0][3] = 7;    table[0][4] = 6;    table[0][5] = 4;    table[0][6] = 13;   table[0][7] = 1;
    table[1][0] = 10;   table[1][1] = 11;   table[1][2] = 8;    table[1][3] = 13;   table[1][4] = 12;   table[1][5] = 11;   table[1][6] = 11;   table[1][7] = 15;
    table[2][0] = 9;    table[2][1] = 4;    table[2][2] = 1;    table[2][3] = 10;   table[2][4] = 7;    table[2][5] = 10;   table[2][6] = 4;    table[2][7] = 13;
    table[3][0] = 2;    table[3][1] = 12;   table[3][2] = 13;   table[3][3] = 1;    table[3][4] = 1;    table[3][5] = 0;    table[3][6] = 1;    table[3][7] = 0;
    table[4][0] = 13;   table[4][1] = 6;    table[4][2] = 10;   table[4][3] = 0;    table[4][4] = 5;    table[4][5] = 7;    table[4][6] = 3;    table[4][7] = 5;
    table[5][0] = 8;    table[5][1] = 13;   table[5][2] = 3;    table[5][3] = 8;    table[5][4] = 15;   table[5][5] = 2;    table[5][6] = 15;   table[5][7] = 7;
    table[6][0] = 0;    table[6][1] = 15;   table[6][2] = 4;    table[6][3] = 9;    table[6][4] = 13;   table[6][5] = 1;    table[6][6] = 5;    table[6][7] = 10;
    table[7][0] = 14;   table[7][1] = 10;   table[7][2] = 2;    table[7][3] = 15;   table[7][4] = 8;    table[7][5] = 13;   table[7][6] = 9;    table[7][7] = 4;
    table[8][0] = 6;    table[8][1] = 2;    table[8][2] = 14;   table[8][3] = 14;   table[8][4] = 4;    table[8][5] = 3;    table[8][6] = 0;    table[8][7] = 9;
    table[9][0] = 11;   table[9][1] = 3;    table[9][2] = 15;   table[9][3] = 4;    table[9][4] = 10;   table[9][5] = 6;    table[9][6] = 10;   table[9][7] = 2;
    table[10][0] = 1;   table[10][1] = 8;   table[10][2] = 12;  table[10][3] = 6;   table[10][4] = 9;   table[10][5] = 8;   table[10][6] = 14;  table[10][7] = 3;
    table[11][0] = 12;  table[11][1] = 1;   table[11][2] = 7;   table[11][3] = 12;  table[11][4] = 14;  table[11][5] = 5;   table[11][6] = 7;   table[11][7] = 14;
    table[12][0] = 7;   table[12][1] = 0;   table[12][2] = 6;   table[12][3] = 11;  table[12][4] = 0;   table[12][5] = 9;   table[12][6] = 6;   table[12][7] = 6;
    table[13][0] = 15;  table[13][1] = 7;   table[13][2] = 0;   table[13][3] = 2;   table[13][4] = 3;   table[13][5] = 12;  table[13][6] = 8;   table[13][7] = 11;
    table[14][0] = 5;   table[14][1] = 5;   table[14][2] = 9;   table[14][3] = 5;   table[14][4] = 11;  table[14][5] = 15;  table[14][6] = 2;   table[14][7] = 8;
    table[15][0] = 3;   table[15][1] = 9;   table[15][2] = 11;  table[15][3] = 3;   table[15][4] = 2;   table[15][5] = 14;  table[15][6] = 12;  table[15][7] = 12;

    key[0] = 0x10CBC8CD;
    key[1] = 0x2FC0CFC5;
    key[2] = 0x34C0CCC1;
    key[3] = 0x92CEC2C8;
    key[4] = 0x81CCD8C3;
    key[5] = 0x705DCDC8;
    key[6] = 0x64C8D8C2;
    key[7] = 0x5ACECBDF;

    quint64 S = 0xAAAAAAAAAAEAAAAA;

    int size = 3;
    quint64* data = new_array_64(size);
    data[0] = 0xAEBAEB63D57B7BBE;
    data[1] = 0xEA7B599A49D9DB6D;
    data[2] = 0xD76F6158CD6DEF5D;
    qDebug()<<"Данные до шифрования";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = replace_encrypt(data,size);
    qDebug()<<"Данные после зашифрования в режиме простой замены";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = replace_decrypt(data,size);
    qDebug()<<"Данные после расшифрования в режиме простой замены";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = gamma(data,size,S);
    qDebug()<<"Данные после зашифрования в режиме гаммирования";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = gamma(data,size,S);
    qDebug()<<"Данные после расшифрования в режиме гаммирования";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = gamma_os(data,size,S);
    qDebug()<<"Данные после зашифрования в режиме гаммирования с обатной связью";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = gamma_os(data,size,S);
    qDebug()<<"Данные после расшифрования в режиме гаммирования с обатной связью";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = imito(data,size);
    qDebug()<<"Имитовставка - зашифрование";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];

    data = imito(data,size);
    qDebug()<<"Имитовставка - расшифрование";
    qDebug()<<"[1] "<<data[0]<<"[2] "<<data[1]<<"[3] "<<data[2];
    return 0;
}

quint64 main_step(quint64 N, quint32 X) {
    quint32 N1= quint32(N);
    quint32 N2 = N>>32;
    quint32 S = N1 + X % 0x100000000;
    bit4 Si[8];
    Si[0] = bit4(S);
    Si[1] = S>>4;
    Si[2] = S>>8;
    Si[3] = S>>12;
    Si[4] = S>>16;
    Si[5] = S>>20;
    Si[6] = S>>24;
    Si[7] = S>>28;

    for(int i=0; i<8; i++) {
        Si[i] = table[Si[i].to_ulong()][i];
    }

    bit32 Si_32;
    int counter = 0;
    for(int i=0; i<8; i++) {
        for(int j=0; j<4; j++) {
            Si_32[counter] = Si[i][j];
            counter++;
        }
    }
    S = Si_32.to_ulong();
     
    S = S<<11;
    S = S^N2;

    N2 = N1;
    N1 = S;

    N = N2;
    N = (N<<32)|N1;
    
    return N;
}

quint64 Z_32(quint64 N) {
    for(int i=0; i<3; i++) {
        for(int j=0; j<8; j++) {
            N = main_step(N,key[j].to_ulong());
        }
    }
    for(int i=7; i>=0; i--) {
        N = main_step(N,key[i].to_ulong());
    }

    quint32 N1= quint32(N);
    quint32 N2 = N>>32;

    N = N1;
    N = (N<<32)|N2;

    return N;
}


quint64 R_32(quint64 N) {
    for(int i=0; i<8; i++) {
        N = main_step(N,key[i].to_ulong());
    }

    for(int i=0; i<3; i++) {
        for(int j=7; j>=0; j--) {
            N = main_step(N,key[j].to_ulong());
        }
    }


    quint32 N1= quint32(N);
    quint32 N2 = N>>32;

    N = N1;
    N = (N<<32)|N2;

    return N;
}

quint64 Z_16(quint64 N) {

    for(int i=0; i<2; i++) {
        for(int j=0; j<8; j++) {
            N = main_step(N,key[j].to_ulong());
        }
    }

    return N;
}

quint64* replace_encrypt(quint64* data, int size_data) {
    for(int i=0; i<size_data; i++) {
        data[i] = Z_32(data[i]);
    }
    return data;
}

quint64* replace_decrypt(quint64* data, int size_data) {
    for(int i=0; i<size_data; i++) {
        data[i] = R_32(data[i]);
    }
    return data;
}

quint64* new_array_64(int size) {
    quint64* A = new quint64[size];
    return A;
}

quint64* gamma(quint64* data, int size,quint64 S) {
    S = Z_32(S);
    for(int i=0; i<size; i++) {
        quint32 S0 = quint32(S);
        quint32 S1 = S>>32;
        S0 = (S0 + C1) % 0x100000000;
        S1 = (S1 + C2 - 1) % 0xFFFFFFFF;
        data[i] = data[i] ^ S;
    }
    return data;
}

quint64* gamma_os(quint64* data, int size, quint64 S) {
    for(int i=0; i<size; i++) {
        data[i] = data[i] ^ Z_32(S);
        S = data[i];
    }
    return data;
}

quint64* imito(quint64 *data, int size) {
    quint64* S = new_array_64(size);
    for(int i=0; i<size; i++) {
        S[i] = 0;
        S[i] = Z_16(S[i]^data[i]);
    }
    return S;
}
