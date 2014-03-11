#include <osrng.h>
#include <chrono>
#include <thread>
#include <iostream>
#include <string>
#include <fstream>
#include <pwdbased.h>
#include <hex.h>
#include <filters.h>
#include <modes.h>
#include <files.h>
#include <secblock.h>
#include <iostream>
#include <string>
#include <aes.h>

using namespace std;
using namespace CryptoPP;

//PROTOTYPES*******************************************************************************************
//*****************************************************************************************************

void Intro();					
void EncryptionRead(string& plaintext); // Read the plaintext from file
void EncDec();
int CloseProgram();

//MAIN*************************************************************************************************
//*****************************************************************************************************

int main() {

	Intro();		// Display program purpose
	EncDec();		// Encrypt or decrypt text file
	return CloseProgram();	// Exit

}

//FUNCTIONS********************************************************************************************
//*****************************************************************************************************
void Intro() {

	/* Function name: Intro
	Author: Caleb Adams
	Written on 3/02/2013
	This function simply displays important preliminary info to user
	Precondition: None
	Postcondition: the purpose of the program is displayed */
	
	cout << "******************************CSCI 466: Project 2*******************************"
		 << "********************************************************************************";

	cout << "\nIn encryption mode, this program will:\n(1) Take as input a password and filename\n"
		 << "(2) Prompt you to select an encryption mode\n(3) Encrypt the file; ciphertext is written "
		 << "in HEX to cipher.txt";

	cout << "\n\nIn decryption mode, this program will:\n(1) Take as input a password and filename\n"
		 << "(2) Prompt you to select a decryption mode\n(3) If the password is correct, produce the "
		 << "plaintext in decrypted.txt";

}
//*****************************************************************************************************
void EncDec() {

	/* Function name: EncDec
	Author: Caleb Adams
	Written on 3/10/2013
	This function reads either encrypts or decrypts a file with AES and various modes of operation
	using PBKDF2
	Precondition: None
	Postcondition: a file is decrpyted/a file is encrypted with one of the modes of operation */

	// plaintext, ciphertext, hextext, decrypted, user password
	string plaintext, cipher, encoded, decrypted, password;
	char action; // For encryption/decryption selection

	PKCS5_PBKDF2_HMAC<SHA256> pbkdf; // PBKDF2
	SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH); // AES key
	
	do {

		// Select encryption or decryption
		cout << "\n\nType the character to select the corresponding mode\n(E = Encrypt, D = "
			 << "Decrypt): ";
		cin >> action;

		if(action == 'E' || action == 'e') {

			int mode; // Mode of operation

			// Prompt user for password for key derivation
			cout << "\n(1) Please enter a password: ";
			cin >> password;

			byte* initV = new byte[AES::BLOCKSIZE]; // IV size of one block
			byte* salt = new byte[AES::DEFAULT_KEYLENGTH]; // Salt value

			// Generate two random numbers - salt and iv
			AutoSeededX917RNG<AES> randomNumGen;
			randomNumGen.GenerateBlock(salt, AES::DEFAULT_KEYLENGTH);
			randomNumGen.GenerateBlock(initV, AES::BLOCKSIZE);

			// Prefix cipher.txt with salt and iv
			StringSource saltSS(salt, AES::BLOCKSIZE, true);
			HexEncoder sink(new FileSink("cipher.txt"));
			saltSS.CopyTo(sink);
			StringSource ivSS(initV, AES::BLOCKSIZE, true);
			ivSS.CopyTo(sink);
			sink.MessageEnd();

			// Read the plaintext file
			EncryptionRead(plaintext);

			// Derive key from password
			pbkdf.DeriveKey(key, key.size(), 0x00, (byte *) password.data(), 
				password.size(), salt, AES::DEFAULT_KEYLENGTH, 20000);

			do { // Select mode of operation until valid

				// Prompt user for mode of op
				cout << "\n(2) Please enter an encryption mode of operation\n    "
					 << "(1 = OFB, 2 = CBC, 3 = CTR, 4 = CFB): ";
				cin >> mode;

				if(mode == 1) { // OFB encryption
					OFB_Mode< AES >::Encryption ofbE;
					ofbE.SetKeyWithIV( key, key.size(), initV );
					StringSource( plaintext, true, 
						new StreamTransformationFilter( ofbE, new StringSink( cipher )));
				}
				else if(mode == 2) { // CBC encryption
					CBC_Mode< AES >::Encryption cbcE;
					cbcE.SetKeyWithIV( key, key.size(), initV );
					StringSource( plaintext, true, 
						new StreamTransformationFilter( cbcE, new StringSink( cipher )));
				}
				else if(mode == 3) { // CTR encryption
					CTR_Mode< AES >::Encryption ctrE;
					ctrE.SetKeyWithIV( key, key.size(), initV );
					StringSource( plaintext, true, 
						new StreamTransformationFilter( ctrE, new StringSink( cipher )));
				}
				else if(mode == 4) { // CFB encryption
					CFB_Mode< AES >::Encryption cfbE;
					cfbE.SetKeyWithIV( key, key.size(), initV );
					StringSource( plaintext, true, 
						new StreamTransformationFilter( cfbE, new StringSink( cipher )));
				}
				else { // Invalid input
					cout << "\nSomething went wrong with encryption mode... try again.";
				}

			// Continue until valid mode is selected
			} while(!(mode == 1 || mode == 2 || mode == 3 || mode == 4));

			// Print ciphertext to cipher.txt in HEX
			StringSource(cipher, true, new HexEncoder(new StringSink( encoded )));

			// Append ciphertext
			ofstream out;
			out.open("cipher.txt", ios::app);
			out << encoded;
			out.close();

			// Done
			cout << "\n(3) Encrypted message written to cipher.txt\n";

			delete [] initV; // delete initialization vector
			delete [] salt;  // delete salt

		}
		else if(action == 'D' || action == 'd') {

			string filename, ctext; // Filename and ciphertext
			ifstream inputFile;		// Input file for reading
			byte iv[AES::BLOCKSIZE]; // Initialization vector
			byte slt[AES::DEFAULT_KEYLENGTH]; // Salt value
			int dmode; // Decryption mode of operation
			
			// Prompt the user for a password for PBKDF2
			cout << "\n(1) Please enter a password: ";
			cin >> password;
	
			// Prompt the user for filename
			cout << "    Please enter the ciphertext filename: ";
			cin >> filename;

			inputFile.open(filename); // Open the file

			// If the file doesn't exist, prompt again
			while(!inputFile) {
				cout << endl << "    Error! File cannot be opened. Ensure your file is in the "
					 << "directory." << endl;
				cout << "    Please enter the ciphertext filename: ";
				cin >> filename;

				inputFile.open(filename); // Open file
			}

			// Read salt from file
			ByteQueue bSlt;
			FileSource f1(inputFile, true, new HexDecoder);
			f1.TransferTo(bSlt, 16);
			bSlt.MessageEnd();
			bSlt.Get(slt, AES::BLOCKSIZE);

			inputFile.close(); // Start over, not sure why but seekg does not work here
			inputFile.open(filename);

			// Read IV from file
			ByteQueue bIV;
			FileSource f2(inputFile, true, new HexDecoder);
			f2.Skip(16);
			f2.TransferTo(bIV);
			bIV.MessageEnd();
			bIV.Get(iv, AES::BLOCKSIZE);

			inputFile.close();  // Start over, not sure why but seekg does not work here
			inputFile.open(filename);

			// Read ciphertext from file
			StringSink s(ctext);
			FileSource f3(inputFile, true, new HexDecoder);
			f3.Skip(32);
			f3.CopyTo(s);

			// Derive decryption key
			pbkdf.DeriveKey(key, key.size(), 0x00, (byte *) password.data(), 
				password.size(), slt, AES::DEFAULT_KEYLENGTH, 20000);

			do { // Select mode of operation until valid input
				cout << "\n(2) Please enter a decryption mode of operation\n    "
					 << "(1 = OFB, 2 = CBC, 3 = CTR, 4 = CFB): ";
				cin >> dmode;

				if(dmode == 1) { // OFB decryption
					OFB_Mode< AES >::Decryption ofbD;
					ofbD.SetKeyWithIV( key, key.size(), iv );
					StringSource( ctext, true, 
						new StreamTransformationFilter( ofbD, new StringSink( decrypted )));
				}
				else if(dmode== 2) { // CBC decryption
					CBC_Mode< AES >::Decryption cbcD;
					cbcD.SetKeyWithIV( key, key.size(), iv );
					StringSource( ctext, true, 
						new StreamTransformationFilter( cbcD, new StringSink( decrypted )));
				}
				else if(dmode == 3) { // CTR decryption
					CTR_Mode< AES >::Decryption ctrD;
					ctrD.SetKeyWithIV( key, key.size(), iv );
					StringSource( ctext, true, 
						new StreamTransformationFilter( ctrD, new StringSink( decrypted )));
				}
				else if(dmode == 4) { // CFB decryption
					CFB_Mode< AES >::Decryption cfbD;
					cfbD.SetKeyWithIV( key, key.size(), iv );
					StringSource( ctext, true, 
						new StreamTransformationFilter( cfbD, new StringSink( decrypted )));
				}
				else { // Invalid input
					cout << "\nSomething went wrong with decryption mode selection... try again.";
				}

			// Keep looping until a valid mode is selected
			} while(!(dmode == 1 || dmode == 2 || dmode == 3 || dmode == 4));

			// Write decrypted plaintext message to decrypted.txt
			ofstream decryptedOutput;
			decryptedOutput.open("decrypted.txt");
			decryptedOutput << decrypted;
			decryptedOutput.close();

			// Done
			cout << "\n(3) Decrypted message written to decrypted.txt\n";

		}
		else // Else encryption/decryption was not chosen, try again
			cout << "\nIncorrect input...try again.";
		
	// Keep looping until a valid mode is selected
	} while(!(action == 'D' || action == 'd' || action == 'e' || action == 'E')); 

		
	return; // Return

}
//*****************************************************************************************************
void EncryptionRead(string& plaintext) {

	/* Function name: EncryptionRead
	Author: Caleb Adams
	Written on 3/02/2013
	This function reads a file and stores its character/string data
	Precondition: a file contains some plaintext message
	Postcondition: The plaintext string is updated */
	
	string filename;	// Filename
	ifstream inputFile;	// Input file
	
	// Prompt user to enter filename
	cout << "    Please enter the plaintext filename: ";
	cin >> filename;

	inputFile.open(filename); // Open the file

	while(!inputFile) { // If the file doesn't exist, prompt again
		cout << endl << "    Error! File cannot be opened. Ensure your file is in the "
			 << "directory." << endl;
		cout << "    Please enter the plaintext filename: ";
		cin >> filename;

		inputFile.open(filename); // Open the file
	}

	// Read the file and store plaintext
	string p((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
	plaintext = p;

	inputFile.close(); // Close the file

	return; // Return

}
//*****************************************************************************************************
int CloseProgram()
{
	/* Function name: CloseProgram
	Author: Caleb Adams
	Written on 2/10/2013
	This function pauses until the user specifies that they wish to exit the program
	Precondition: None
	Postcondition: The program terminates */

	cout << endl;

	system("PAUSE");  // Wait for user

	return 0;		  // This is the end of my program
}
//*****************************************************************************************************
