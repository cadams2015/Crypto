Date: 3/11/14

Comments: You should/need to have a plaintext file in the .exe
directory (I provided plain.txt, which contains a simple message). The 
interface should be pretty self explanatory. It's not bulletproof, but 
there is basic input checking. The plaintext message should be in a .txt file. 
The tool will encrypt/decrypt with OFB, CBC, CTR, or CFB as you choose. However, 
if the user encrypts a file with a specific mode, they must remember the mode for 
proper decryption. The program will encode the ciphertext in hexadecimal in cipher.txt. 
It will also prefix the ciphertext with the hexadecimal representation of 
both the initialization vector and salt, which are generated randomly upon 
execution so they must be stored with the cipher. You may rename the cipher.txt 
file after encryption and decryption will still function properly as long as you 
input the correct file name during the decryption mode. I also put some 
screenshots of execution in the archive. I tested this with all modes and various 
plaintexts, and it seemed to work sufficiently. However, the only uncertainty was
the reliability of the RNG I used for salt and IV. All source code is in main.cpp

Compilation Environment: Microsoft VS 2012
Run: P2.exe
Implemented using the Crypto++ library for C++
