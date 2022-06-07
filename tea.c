#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define SIZE_INT sizeof(int) * 8
#define MAX_SIZE 5000

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 


unsigned short int* generate_key_array(unsigned short int K);
int SBoxFunc(int  ur);
int PBoxFunc(int  vr);
void ReverseSBox();
void ReversePBox();
int SPNfunc(int x, unsigned short int*ks);
int encrypt(unsigned short int* Ks,int x);
int decrypt(unsigned short int* Kstmp, int y);

//             0, 1, 2,  3, 4, 5, 6, 7,  8, 9, 10, 11, 12,13,14, 15 
int SBox[] = {6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11};
//             1, 2, 3, 4,  5, 6, 7,  8,  9, 10,11, 12, 13,14,15, 16
int PBox[] = {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16};


//Array with messages 
char bufferMessages[10][2] = {{'N','W'}, {'D','L'}, {'E','R'}, {'R','L'}, {'P','Y'}, {'V','T'}, {'E','N'}, {'Z','Y'}, {'K','D'}, {'B','M'}};

//Array with keys 
unsigned short int bufferKeys[10] = {5128, 346, 3905, 68, 3457, 6578, 3478, 1067, 3254, 789};

//Function for filling a file with Encrypted text 
void encrypt1GBFile(unsigned short int* Ks)
{
    int flag = 0;
    FILE *file, *fp, *fp1;
    // open the file for writing if it exists
    if ((file = fopen("text4.txt", "r"))) {
        printf("Encrypted file already exists.");
        fclose(file);
    }
    else {
        flag = 1;
    }
    printf("\nEncrypting 1GB file...\n");
    char *filename = "text3.txt";
    char *filename1 = "text4.txt";
    char firstLetter,secondLetter;
    
    unsigned short int mask1 = 0b1111111100000000;
    unsigned short int mask2 = 0b0000000011111111;
    
    unsigned short int CypherLetter1,CypherLetter2;
    // open the file for writing
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        printf("Error opening the file %s", filename);
    }
    
    if(flag) {
        fp1 = fopen(filename1, "w");
        if (fp1 == NULL)
        {
            printf("Error opening the file %s", filename1);
        }
    }
    
    while(!feof(fp)) {
	    fscanf(fp,"%c", &firstLetter);
	    fscanf(fp,"%c", &secondLetter);
        
	    unsigned short int x1 = firstLetter;
	    x1 = x1 << 8;
	    unsigned short int x2 = secondLetter;
	    int X = x1 | x2;
	   
	    unsigned short int enc = encrypt(Ks, X);
	    
        if(flag == 1) {
            CypherLetter1 = ((enc & mask1)>>8);
            CypherLetter2 = (enc & mask2);
            fprintf(fp1, "%c%c", CypherLetter1, CypherLetter2);
        }
    }
    fclose(fp);
    if(flag == 1) {
        fclose(fp1);
    }
}


//Function for Decrypting the existing file (with Encrypted text)
void decrypt1GBFile(unsigned short int* Ks) {

    printf("\nDecrypting 1GB file...\n");
    char *filename = "text4.txt";
    char firstLetter, secondLetter;
    
    // open the file for writing
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Error opening the file %s", filename);
    }
    
    while (!feof(fp)) {

	    fscanf(fp,"%c", &firstLetter);
	    fscanf(fp,"%c", &secondLetter);

	    if (firstLetter == '\n') {
	    	fscanf(fp,"%c", &firstLetter);
        }
	    if (secondLetter == '\n') {
	    	fscanf(fp,"%c", &secondLetter);
        }
	   

	    unsigned short int x1 = firstLetter;
	    x1 = x1 << 8;
	    unsigned short int x2 = secondLetter;

	    int X = x1 | x2;
	   
	    unsigned short int dec = decrypt(Ks,X);
	    
    }
    fclose(fp);
}


//Function for fill a file with  (M,C) with Key=0 
void writeFile(unsigned short int* Ks)
{
    char *filename = "text1.txt";

    // open the file for writing
    FILE *fp = fopen(filename, "w");
    if (fp == NULL)
    {
        printf("Error opening the file %s\n", filename);
    }

    fprintf(fp, "Encryption(C) message is presented in Decimal form (Message, Encrypted Message).\n");
    // write to the text file

     unsigned short int firstMessageLetter;
     unsigned short int secondMessageLetter;
     int X ;
    for (int i = 0; i < 10; i++){
        firstMessageLetter = bufferMessages[i][0];
        firstMessageLetter = firstMessageLetter << 8;
        secondMessageLetter = bufferMessages[i][1];

        //Combine two letters
        X = firstMessageLetter | secondMessageLetter;

        int enc = encrypt(Ks, X);
        
        unsigned short int enc2=enc;

        unsigned char chipherLetter1 =  (enc2 & 0b1111111100000000) >> 8;
        
        unsigned char chipherLetter2 = enc2 ;

        fprintf(fp, "(%c%c,%d %d)\n", bufferMessages[i][0], bufferMessages[i][1],chipherLetter1,chipherLetter2 );

    }

    // close the file
    fclose(fp);
}


//Function for fill a file with  (K,C) with M=0 
void writeFile2(unsigned short int M)
{
    char *filename = "text2.txt";

    // open the file for writing
    FILE *fp = fopen(filename, "w");
    if (fp == NULL)
    {
        printf("Error opening the file %s", filename);
    }
    fprintf(fp, "Key(K) and Encryption(C) message is presented in Decimal form (Key, Encrypted Message).\n");
    // write to the text file
   
    for (int i = 0; i < 10; i++) {
       
        unsigned short int* Ks = generate_key_array(bufferKeys[i]);

        int enc = encrypt(Ks, M);

        unsigned short int enc2=enc;

        unsigned char chipherLetter1 =  (enc2 & 0b1111111100000000) >> 8;
        
        unsigned char chipherLetter2 = enc2 ;

        fprintf(fp, "(%d,%d %d)\n", bufferKeys[i],chipherLetter1,chipherLetter2 );
    }

    // close the file
    fclose(fp);
}

void create_random_Text() {
    FILE *file;
    // open the file for writing if it exists
    if ((file = fopen("text3.txt", "r"))) {
        printf("Message file already exists.");
        fclose(file);
    }
    else {
        char *filename = "text3.txt";

        int size = (int)pow(2,26);
        char a,b,c,d,e,f,g,h,i,j,k,l,m,n,o;
        
        // open the file for writing
        FILE *fp = fopen(filename, "w");
        if (fp == NULL)
        {
            printf("Error opening the file %s", filename);
        }
        
        while(size) {
            a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            b = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            c = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            d = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            e = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            f = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            g = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            h = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            i = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            j = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            k = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            l = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            m = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            n = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
            o = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random()%26];
        
            fprintf(fp, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", a,b,c,d,e,f,g,h,i,j,k,l,m,n,o);
            size--;
        }

        // close the file
        fclose(fp);
    }
}

int main(void) {

    unsigned short int K;
    unsigned short int* Ks;

    char input[MAX_SIZE];
    while(1) {
        printf("Press (1) for encryption with K=0\n");
        printf("Press (2) for encryption with M=0\n");
        printf("Press (3) to print keys statring with K=a1e9\n");
        printf("Press (4) to see encryption and decryption execution time of 1Gb file\n");
        printf("Press (5) to exit.\n");
        scanf("\n%s", input);
        if(strlen(input) > 1){
        	continue;
		}
        else if(atoi(input) == 1) {
            K = 0b0000000000000000;
            printf("Key list with input key = 0: \n");
            Ks = generate_key_array(K);
            writeFile(Ks);
            printf("File 1 created (text1.txt).\n\n");
        }
        else if(atoi(input) == 2) {
            printf("Cipher list with input message = 0 : \n");
            writeFile2(0b0000000000000000);     //<----M=0
            printf("File 2 created (text2.txt).\n\n");
        }
        else if(atoi(input) == 3) {
            K = 0b1010000111101001;
            printf("Key list with input key = a1e9 (in hex) : \n");
            Ks = generate_key_array(K);
            int i;
            for(i=0; i<5; i++) {
                printf("Key%d===>%hu\n", i, Ks[i]);
            }
            printf("\n");
        }
        else if(atoi(input) == 4) {
            unsigned short int K = 0b0000000000000000;
            create_random_Text();
            Ks = generate_key_array(K);
            
            clock_t t1;
            t1 = clock();
            encrypt1GBFile(Ks);
            t1 = clock() - t1;
            double time_taken1 = ((double)t1)/CLOCKS_PER_SEC;   //calculate the elapsed time
            printf("The program took %f seconds to encrypt 1GB file with 2^26 messages in text4.txt.\n", time_taken1);

            clock_t t2;
            t2 = clock();
            decrypt1GBFile(Ks);
            t2 = clock() - t2;
            double time_taken2 = ((double)t2)/CLOCKS_PER_SEC;   //calculate the elapsed time
            printf("The program took %f seconds to decrypt 1GB file with 2^26 messages.\n", time_taken2);

            printf("\n");
        }
        else if(atoi(input) == 5) {
            break;
        }
        else {
            continue;
        }
    }
    return 0;
}


//Generate five 16-bit keys from 32-bit key 
unsigned short int*  generate_key_array(unsigned short int K) {

    static unsigned short int Ks[5];
    static unsigned short int TmpKs[2];
    static unsigned short int TmpKs2[2];
    static unsigned short int TmpKs3[2];
    int i;
    //Masks for taking the First and Second half of 16-bit
    unsigned short int half1Mask = 0b1111111100000000;
    unsigned short int half2Mask = 0b0000000011111111;

    for(i=4; i>=0; i--) {
        
        TmpKs[0] = K & half1Mask;
        TmpKs[1] = K & half2Mask;

        Ks[i] = TmpKs[0] | TmpKs[1];
       
        static unsigned char FirstHalf;
        FirstHalf=TmpKs[0] >> 8;
        static unsigned char SecondHalf;
        SecondHalf=TmpKs[1];

        //Left Rotate Shift
        FirstHalf = (FirstHalf << 2) | (FirstHalf >> (8 - 2));
        SecondHalf = (SecondHalf << 2) | (SecondHalf >> (8 - 2));

        if (i != 1) {

            TmpKs2[0] = FirstHalf & 0b11110000;     
            TmpKs2[0] = TmpKs2[0] << 8;        

            TmpKs2[1] = FirstHalf & 0b00001111;      
            TmpKs2[1] = TmpKs2[1] << 4;     

            TmpKs3[0] = SecondHalf & 0b11110000;     
            TmpKs3[0] = TmpKs3[0] << 4;      

            TmpKs3[1] = SecondHalf & 0b00001111;     

            K = TmpKs2[0] | TmpKs2[1] | TmpKs3[0] | TmpKs3[1];  
        }
        else {
            FirstHalf = (K & 0b1111111100000000) >> 8;
            SecondHalf = K & 0b0000000011111111;

            //Left Rotate Shift
            FirstHalf = (FirstHalf << 2) | (FirstHalf >> (8 - 2));
            SecondHalf = (SecondHalf << 2) | (SecondHalf >> (8 - 2));

            TmpKs2[0] = FirstHalf; 
            TmpKs2[0] = TmpKs2[0] << 8;   

            TmpKs2[1] = SecondHalf;      
    
            K = TmpKs2[0] | TmpKs2[1];
        }
    }
    return Ks;
}

//Substitution Function
int SBoxFunc(int ur) {
    int vr=0, i, uri=0, vri=0;
    for(i=0;i<4;i++) {
        uri = ur % ((int) pow(2,4));

        vri = SBox[uri];
        
        vr = vr + (vri << (4 * i));
        ur = ur >> 4;
    }
    return vr;
}

//Permutation Function
int PBoxFunc(int  vr) {
    int wr = 0, i, vri=0;
    for(i = 15; i > -1 ; i--) {
        vri = vr % 2;
        vr = vr >> 1;
        wr = wr + (vri << (16 - PBox[i]));
    }
    return wr;
}


//Finding the reverse Sbox for Decryption
void ReverseSBox() {
    int SBoxTmp[16] ;
    int i;
    for(i=0;i<16;i++){
        SBoxTmp[i]=SBox[i];
    }
    for(i=0; i<16; i++) {
        SBox[SBoxTmp[i]] = i;
    }
}

//Finding the reverse Pbox for Decryption
void ReversePBox() {
    int PBoxTmp[16];
    int i;
    for(i=0;i<16;i++) {
        PBoxTmp[i] = PBox[i];
    }
    
    for(i=0; i<16; i++) {
        PBox[PBoxTmp[i]-1] = i+1;
    }
}


//Function for making the SPN Network
int SPNfunc(int x, unsigned short int* ks) {
    int wr=x, r=0, ur=0, vr=0, y=0;
    //First 3 rounds
    for(r = 0; r<3; r++) {
        ur = wr ^ ks[r];
        vr = SBoxFunc(ur);
        wr = PBoxFunc(vr);
    }
    //4th round
    ur = wr ^ ks[3];
    vr = SBoxFunc(ur);
    //Last Round
    y = vr ^ ks[4];
    return y;
}

//Function for Encryption
int encrypt(unsigned short int* Ks, int x) {
    return SPNfunc(x, Ks);
}


//Function for Decryption
int decrypt(unsigned short int* Kstmp, int y) {
    unsigned short int *Ks = Kstmp;
    int ksTmp[] = {0,0,0,0,0};
	int i;
	
    //Copping the key array to a local key array
    for(i = 0; i<5; i++) {
        ksTmp[i] = Ks[i];
    }
    int j=4;

    //====Reverse=====
    for(i = 0; i<5; i++) {
        Ks[i] = ksTmp[j];
        j--;
    }

    Ks[1] = PBoxFunc( Ks[1]);
    Ks[2] = PBoxFunc( Ks[2]);
    Ks[3] = PBoxFunc( Ks[3]);

    ReverseSBox();
    ReversePBox();

    return SPNfunc(y, Ks);
}
