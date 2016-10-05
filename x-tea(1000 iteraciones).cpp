#include <iostream>
#include <fstream>
#include <stdint.h>
#include <cstring>
#include <time.h>
#include "sys/types.h"
#include "sys/sysinfo.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

using namespace std;

struct sysinfo memInfo;
unsigned int key[4]={0x27F917B1,0xC1DA8993,0x60E2ACAA,0xA6EB923D}; // encryption key
int parseLine(char* line){
    // This assumes that a digit will be found and the line ends in " Kb".
    int i = strlen(line);
    const char* p = line;
    while (*p <'0' || *p > '9') p++;
    line[i-3] = '\0';
    i = atoi(p);
    return i;
}

#define BLOCK_SIZE 8
void xtea_encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void xtea_decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) xor (v0 >> 5)) + v0) xor (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) xor (v1 >> 5)) + v1) xor (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void StringCrypt(char *inout,int len,bool encrypt)
{
  for(int i=0;i<len/BLOCK_SIZE;i++)
    {
      if(encrypt)
          xtea_encipher(32,(uint32_t*)(inout+(i*BLOCK_SIZE)),key);
      else
          xtea_decipher(32,(uint32_t*)(inout+(i*BLOCK_SIZE)),key);
    }
  if(len%BLOCK_SIZE!=0)
    {
        int mod=len%BLOCK_SIZE;
        int offset=(len/BLOCK_SIZE)*BLOCK_SIZE;
        char data[BLOCK_SIZE];
        memcpy(data,inout+offset,mod);

        if(encrypt)
            xtea_encipher(32,(uint32_t*)data,key);
        else
            xtea_decipher(32,(uint32_t*)data,key);

        memcpy(inout+offset,data,mod);
    }
}
int getValue(){ //Note: this value is in KB!
    FILE* file = fopen("/proc/self/status", "r");
    int result = -1;
    char line[128];

    while (fgets(line, 128, file) != NULL){
        if (strncmp(line, "VmRSS:", 6) == 0){
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    return result;
}
void FileCrypt(string filename,bool encrypt)
{
  fstream file(filename.c_str(),ios::in | ios::out | ios::binary);
	
  if(!file)
    {
      cout <<"Could not open file";
      return;
    }

  unsigned size;

  file.seekg(0,ios::end);
  size=file.tellg();
  file.seekg(ios::beg);

  file.clear();

  unsigned pos;

  int n_blocks=size/BLOCK_SIZE;
  if(size%BLOCK_SIZE!=0)
      ++n_blocks;

  for(int i=0;i<n_blocks;i++)
    {
      unsigned char data[BLOCK_SIZE];
      pos=file.tellg();

      file.read((char*)data,BLOCK_SIZE); // read data block
		
      if(encrypt)
          xtea_encipher(32,(uint32_t*)data,key);
      else
          xtea_decipher(32,(uint32_t*)data,key);

      file.seekp(pos);
      file.write((char*)data,BLOCK_SIZE);

      memset(data,0,BLOCK_SIZE);
    }
  file.close();
}

int main()
{
	unsigned int p1[2]={0xAF20A390,0x547571AA};

	sysinfo (&memInfo);
	long totalPhysMem = memInfo.totalram;
	totalPhysMem *= memInfo.mem_unit;
  clock_t start, finish, time_encryption[100000], time_decryption[100000], startTime;
  startTime=clock();
  float ram[100000];
  for (int i=0; i<100000; i++){
	start = clock();
	xtea_encipher(32, (uint32_t*)p1, key);
	finish=clock();
	time_encryption[i]=(finish-start);
	
	start = clock();
	xtea_decipher(32, (uint32_t*)p1, key);
	finish=clock();
	time_decryption[i]=(finish-start);
	ram[i]=getValue();
	
  }
  double suma, suma_ram;
  for(int i=0;i<100000;i++){
	suma+=time_decryption[i];
	suma_ram+=ram[i];
  }
  float suma1;
  for(int i=0;i<100000;i++){
	suma1+=time_encryption[i];
	suma1+= time_encryption[i] / (double)CLOCKS_PER_SEC;
  }
  cout<<"RAM usage: "<<suma_ram/10000<<" KB\n";
  cout<<"Average encryptiying time: "<<(suma1/100000)/ (double)CLOCKS_PER_SEC<<" seconds"<<endl;  
  cout<<"Average decryptiying time: "<<(suma/100000)/ (double)CLOCKS_PER_SEC<<" seconds"<<endl;  
  cout << "Total excecution time: "<<double( clock() - startTime ) / (double)CLOCKS_PER_SEC<< " seconds." << endl; 
	
}
