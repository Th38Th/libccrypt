#include "rsa.h"
#include "primes.h"
#include <iostream>
using namespace std;

mpz_class RSA::encrypt(char c, rsa_key key)
{
    mpz_class result;
    mpz_class base = c;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), key.second.get_mpz_t(), key.first.get_mpz_t());
    return result;
}
char RSA::decrypt(mpz_class c, rsa_key key)
{
    mpz_class result;
    mpz_class base = c;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), key.second.get_mpz_t(), key.first.get_mpz_t());
    return (char)result.get_ui();
}
rsa_key_pair RSA::get_keys(mpz_class p, mpz_class q)
{
    rsa_key_pair result;
    mpz_class d;
    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);
    mpz_class e = 65537;
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
    result.first.first = result.second.first = n;
    result.first.second = e;
    result.second.second = d;
    return result;
}

/** 
 * @param maxb The upper bound for the prime numbers.
 * 
 * Initializes an instance of RSA with bounded @c P and @c Q.
 * 
 * @c P and @c Q are not stored, only the keys are.
 *  
**/
RSA::RSA(mpz_class maxb)
{
    if(maxb ==-1) maxb = 2e4;
    auto p = get_random_prime(maxb,maxb/2);
    auto q = get_random_prime(p/2,p/4);
    auto k = get_keys(p, q);
    public_key = k.first;
    private_key = k.second;
}
rsa_ciphertext RSA::encrypt(string message)
{
    rsa_ciphertext result(message.length(), 0);
    for (int i = 0; i < message.length(); i++)
        result[i] = encrypt(message[i], public_key);
    return result;
}
string RSA::decrypt(const rsa_ciphertext& message)
{   
    string result(message.size(), 0);
    for (int i = 0; i < message.size(); i++)
        result[i] = decrypt(message[i], private_key);
    return result;
}
vector<uint8_t> RSA::serialize_ciphertext(const rsa_ciphertext& ciphertext)
{
    std::vector<uint8_t> serialized_data;

    for (const auto& number : ciphertext) {
        // Convert mpz_class to a byte array
        size_t size = (mpz_sizeinbase(number.get_mpz_t(), 2) + 7) / 8;
        std::vector<uint8_t> bytes(size);
        mpz_export(bytes.data(), &size, 1, 1, 0, 0, number.get_mpz_t());

        // Append the size of the byte array as 2 bytes
        serialized_data.push_back(static_cast<uint8_t>(size >> 8));
        serialized_data.push_back(static_cast<uint8_t>(size & 0xFF));

        // Append the byte array
        serialized_data.insert(serialized_data.end(), bytes.begin(), bytes.end());
    }

    return serialized_data;
}
rsa_ciphertext RSA::deserialize_ciphertext(const vector<uint8_t>& data)
{
    rsa_ciphertext ciphertext;
    size_t index = 0;

    while (index < data.size()) {
        // Read the size of the next mpz_class
        size_t size = (data[index] << 8) | data[index + 1];
        index += 2;

        // Extract the bytes corresponding to this mpz_class
        std::vector<uint8_t> bytes(data.begin() + index, data.begin() + index + size);
        index += size;

        // Convert bytes to mpz_class
        mpz_class number;
        mpz_import(number.get_mpz_t(), bytes.size(), 1, 1, 0, 0, bytes.data());
        ciphertext.push_back(number);
    }

    return ciphertext;
}
#ifdef __RSA_X_DBG_FLG__
    void RSA::debug_print()
    {
        cout<<"RSACrypt {";
        cout<<"PubKey: ("<<public_key.first.get_str()<<","<<public_key.second.get_str()<<") | ";
        cout<<"PrivKey: ("<<private_key.first.get_str()<<","<<private_key.second.get_str()<<")";
        cout<<"}"<<endl;
    }
#endif