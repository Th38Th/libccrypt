#include <gmp.h>
#include <gmpxx.h>
#include <utility>
#include <string>
#include <vector>
#include <cstdint>
using namespace std;

typedef pair<mpz_class,mpz_class> rsa_key;
typedef pair<rsa_key,rsa_key> rsa_key_pair;
typedef vector<mpz_class> rsa_ciphertext;

/**
*    @brief A class encapsulating the RSA cryptographic algorithm,
*    enabling encryption/decryption. 
*    
*    It generates its own public and private keys.
**/
class RSA
{
    rsa_key public_key, private_key;
    static mpz_class encrypt(char, rsa_key);
    static char decrypt(mpz_class, rsa_key);
    static rsa_key_pair get_keys(mpz_class, mpz_class);
    public:  
        RSA(mpz_class=-1);
        rsa_ciphertext encrypt(string);
        string decrypt(const rsa_ciphertext&);
        #ifdef __RSA_X_DBG_FLG__
            void debug_print();
        #endif
        static vector<uint8_t> serialize_ciphertext(const rsa_ciphertext& vec);
        static rsa_ciphertext deserialize_ciphertext(const vector<uint8_t>& vec);
};