#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "rsa.h"
#include "aes.h"
#include "aes-modes.h"
#include <iostream>
#include <iomanip>
#include <windows.h>
using namespace std;

void test_rsa(){
    RSA rsa(3e4);
    #ifdef __RSA_X_DBG_FLG__
        rsa.debug_print();
    #endif
    cout << "Testing RSA Encryption" << endl;
    while(true){
        cout << "Message is: (blank to quit)" << endl << ">\t";
        std::string msg;
        getline(cin, msg);
        if (msg.empty()) break;
        auto enc = rsa.encrypt(msg);
        cout << "Encrypted is: [";
        for (int i = 0; i < enc.size(); i++)
            cout << enc[i].get_str() << " ";
        cout << "]" << endl;
        auto srz = RSA::serialize_ciphertext(enc);
        auto dsrz = RSA::deserialize_ciphertext(srz);
        auto dec = rsa.decrypt(dsrz);
        cout << "Decrypted is: \"" << dec << "\"" << endl;
    }
    cout << "RSA Test Finished!" << endl;
}


void test_aes(){
    //auto ecb = std::make_shared<AES::ECB>(); 
    auto cbc = std::make_shared<AES::CBC>(16);
    AES::AES aes(256, 128, cbc);
    #ifdef __AES_X_DBG_FLG__
        aes.debug_print(0);
    #endif
    cout << "Testing AES Encryption" << endl;
    while(true)
    {
        cout << "Message is: (blank to quit)" << endl << ">\t";
        std::string msg;
        getline(cin, msg);
        if (msg.empty()) break;
        auto enc = aes.encrypted(msg);
        cout << "Encrypted is: [" << hex;
        for (int i = 0; i < enc.length(); i++)
            cout << setfill('0') << setw(2)
                 << (int)(enc.data()[i] & 0xFF) << " ";
        cout << "]" << endl;
        auto dec = aes.decrypted(enc);
        cout << "Decrypted is: \"" << dec << "\"" << endl;
    }
    cout << "AES Test Finished!" << endl;
}

int main()
{
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    while(true) {
        cout << "Which encryption algorithm would you like to test?" << endl;
        cout << "1. RSA" << endl;
        cout << "2. AES" << endl;
        cout << "3. <coming soon>" << endl;
        cout << "................" << endl;
        cout << "[-1] quit" << endl;
        cout << ">\t";
        int choice = -1;
        cin >> choice;
        cin.get();
        switch (choice)
        {
            case 1:
                test_rsa();
                break;

            case 2:
                test_aes();
                break;

            default:
                break;
        }
        if (choice == -1)
            break;
    }
    cout << "Thank you, see you next time!" << endl;
    cout << "Press any key to exit..." << endl;
    cin.get();
    return 0;
}