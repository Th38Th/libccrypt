#include "aes-modes.h"

void AES::CBC::set_iv(byte_array iv) { this->iv = iv; }
byte_array AES::CBC::get_iv() { return this->iv; }
void AES::CBC::init_random_iv(size_t size = 16) { 
    iv.resize(size);
    generate_key(this->iv); 
}

AES::CBC::CBC(size_t block_size = 16) : iv(block_size) {}

inline void xor_arrays(uint8_t* a, const uint8_t* b, size_t size) {
    for (size_t i = 0; i < size; i++)
        a[i] ^= b[i];
}

std::string AES::CBC::encrypted(const BlockEncryption* prn, std::string m) const {
    m = std::string((char*)iv.data(), iv.size()) + m;
    size_t block_size = get_block_size(prn);
    size_t int_block_sz = m.length()/block_size;
    auto res = pad_string(m, block_size, &int_block_sz);
    auto r_p = (uint8_t*)res.data();
    auto r_pp = new uint8_t[block_size];
    for (size_t i = 0; i < int_block_sz; i++) {
        if (i > 0) xor_arrays(
            r_p + i*block_size,
            r_pp, block_size);
        memcpy(r_pp, r_p + i*block_size, block_size);
        encrypt_block(prn, r_p + i*block_size);
    }
    delete[] r_pp;
    res += res.length() - m.length();
    return res;
}

std::string AES::CBC::decrypted(const BlockEncryption* prn, std::string c) const{
    size_t block_size = get_block_size(prn);
    size_t int_block_sz = c.length() / block_size;
    size_t pad = c.back();
    c = c.substr(0, c.length() - 1);
    auto res = pad_string(c, block_size, &int_block_sz);
    auto r_p = (uint8_t*)res.data();
    for (size_t i = 0; i < int_block_sz; i++) {
        decrypt_block(prn, r_p + i*block_size);
        if (i > 0) xor_arrays(
            r_p + i*block_size,
            r_p + (i-1)*block_size,
            block_size);
    }
    res = res.substr(iv.size(), res.length());
    return pad? res.substr(0, res.length() - pad): res;
}