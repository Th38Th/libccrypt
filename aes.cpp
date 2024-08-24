#include "aes.h"
#include <string.h>
#include <math.h>
#include <random>
#include <algorithm>
#include <iomanip>
#include <iostream>
using namespace AES;

uint8_t g_mult(uint8_t a, uint8_t b){
    uint8_t p = 0;
    for (size_t i = 0; i < 8; i++){
        if (b & 1) p ^= a;
        uint8_t carry = a & 0x80;
        a <<= 1;
        a &= 0xFF;
        if (carry) 
            a ^= 0x1B;
        b >>= 1;
    }
    return p & 0xFF;
}

uint8_t ROTL8(uint8_t x, uint8_t n) {
    return (x << n) | (x >> (8 - n));
}

uint8_t* AES::SBox::gen_box(bool inv=false){
    uint8_t* buf = new uint8_t[256];
    memset(buf, 0, 256);
    uint8_t* tmp = inv? new uint8_t[256]: buf;
    if (inv) memset(tmp, 0, 256);
	uint8_t p = 1, q = 1;
	
	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		tmp[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	tmp[0] = 0x63;

    if (inv) {
        for (size_t i = 0; i < 256; ++i)
            buf[tmp[i]] = static_cast<uint8_t>(i);
        delete[] tmp;
    }

    return buf;
}

uint8_t AES::SBox::sub(uint8_t x) const{
    return s_box[x];
}

uint8_t AES::SBox::inv(uint8_t x) const{
    return s_inv[x];
}

AES::SBox::SBox(){
    s_box = gen_box();
    s_inv = gen_box(true);
}

AES::SBox::~SBox(){
    if(s_box != nullptr) delete[] s_box;
    if(s_inv != nullptr) delete[] s_inv;
}

void BaseKeySchedule::rot_word(uint8_t* word, size_t size) {
    uint8_t l = word[0];
    for (size_t i = 0; i < size - 1; i++)
        word[i] = word[i+1];
    word[size - 1] = l;
}

void BaseKeySchedule::xor_word(uint8_t* word1, uint8_t* word2, size_t size) {
    for (size_t i = 0; i < size; i++)
        word1[i] = word1[i] ^ word2[i];
}

void BaseKeySchedule::sub_word(uint8_t* word, size_t size){
    if (this->s_box != nullptr)
        for (size_t i = 0; i < size; i++)
            word[i] = this->s_box->sub(word[i]);
}

void BaseKeySchedule::rebuild(){
    if (this->rc != nullptr)
        delete[] this->rc;
    if (this->w != nullptr)
        delete[] this->w;
    this->rc = this->generate_rc();
    this->w = this->generate_w();
}

const uint8_t* BaseKeySchedule::generate_rc() { return nullptr;}
const uint8_t* BaseKeySchedule::generate_w() { return nullptr;}
void BaseKeySchedule::get_rcon(size_t idx, uint8_t* dst ) { }

BaseKeySchedule::BaseKeySchedule(size_t key_size, size_t block_size, const SBox* s_box){
    this->s_box = s_box;
    this->block_size = block_size;
    aes_key key(key_size, 0);
    generate_key(key);
    this->key = key;
}

BaseKeySchedule::BaseKeySchedule(const aes_key& key, size_t block_size, const SBox* s_box){
    this->s_box = s_box;
    this->block_size = block_size;
    this->key = key;
}

BaseKeySchedule::~BaseKeySchedule(){
    if (this->rc != nullptr){
        delete[] rc;
        rc = nullptr;
    }
    if (this->w != nullptr) {
        delete[] w;
        w = nullptr;
    }
}

size_t BaseKeySchedule::get_num_words() const {
    size_t R = get_num_rounds();
    size_t N = get_key_length();
    size_t word_count = 4 * R - 1;
    return word_count;
}

size_t KeySchedule::get_num_words() const {
    return BaseKeySchedule::get_num_words();
}

aes_key BaseKeySchedule::get_round_key(size_t idx) const {
    idx = idx % get_num_words();
    aes_key k(block_size, 0);
    for (size_t i = 0; i < block_size; i++)  
        k[i] = w[idx * block_size + i];
    return k;
}

size_t BaseKeySchedule::get_key_length() const{
    return key.size() / 4;
}

size_t BaseKeySchedule::get_num_rounds() const{
    return std::max(get_key_length(), block_size/4)+7;
}

AES::KeySchedule::KeySchedule
(const aes_key& key, size_t block_size, const SBox* s_box)
 : BaseKeySchedule(key, block_size, s_box) 
 { this->rebuild(); }

AES::KeySchedule::KeySchedule
(size_t key_size, size_t block_size, const SBox* s_box)
 : BaseKeySchedule(key_size, block_size, s_box) 
 { this->rebuild(); }

AES::KeySchedule::~KeySchedule() {}

const uint8_t* KeySchedule::generate_rc(){
    uint8_t* result = new uint8_t[11];
    memset(result, 0, 11);
    for (size_t i = 0; i < 11; i++){
        uint16_t e = 1;
        if (i > 0){
            e = result[i-1] << 1;
            if (e > 0x80)
                e ^= 0x11B; 
        }
        result[i] = e;
    }
    return result;
}

void KeySchedule::get_rcon(size_t idx, uint8_t* dst){
    dst[0] = rc[idx];
    memset(dst+1,0,3);
}

const uint8_t* KeySchedule::generate_w(){
    size_t R = get_num_rounds();
    size_t N = get_key_length();
    size_t word_count = 4 * R - 1;
    uint8_t* result = new uint8_t[word_count*4+1];
    memset(result, 0, word_count*4 + 1);
    uint8_t e[4] = {0}, 
    p[4] = {0}, pp[4] = {0}, 
    rcon[4] = {0};
    for (size_t i = 0; i < word_count; i++){
        if (i >= N) {
            memcpy(p, result + (i-1)*4, 4);
            memcpy(pp, result + (i-N)*4, 4);
            if (i % N == 0){
                get_rcon(i/N, rcon);
                rot_word(p, 4);
                sub_word(p, 4);
                xor_word(pp, p, 4);
                xor_word(pp, rcon, 4);
                memcpy(result + i*4, pp, 4);
            }
            else if (N > 6 && i % N == 4) {
                sub_word(p, 4);
                xor_word(pp, p, 4);
                memcpy(result + i*4, pp, 4);
            }
            else {
                xor_word(pp, p, 4);
                memcpy(result + i*4, pp, 4);
            };
        }
        else {
            memcpy(e, key.data() + i*4, 4);
            memcpy(result + i*4, e, 4);
        }
    }
    return result;
}

size_t AES::AES::get_num_rounds() const{
    return std::max(k_schedule->get_key_length(), block_size/4)+7;
}

size_t AES::AES::get_key_size() const{
    return k_schedule->get_key_length();
}

void AES::generate_key(aes_key& dst){
    // Random number generator setup
    std::random_device rd;  // Seed for the random number engine
    std::mt19937 gen(rd()); // Mersenne Twister engine initialized with random_device
    std::uniform_int_distribution<uint16_t> dis(0, 255); // Range of a byte (0 to 255)

    // Generate the random byte array
    for (std::size_t i = 0; i < dst.size(); i++) {
        dst[i] = static_cast<uint8_t>(dis(gen));
    }
}

AES::AES::AES(size_t key_size, size_t block_size=128
, std::shared_ptr<OperationMode> ptr = nullptr) {
    this->block_size = block_size / 8;
    row_size = sqrt(this->block_size);
    col_size = row_size;
    s_box = new SBox();
    k_schedule = new KeySchedule(
        key_size / 8, this->block_size,
        s_box);
    o_mode = ptr != nullptr? ptr:
     std::make_shared<ECB>();
}

AES::AES::AES(const aes_key& key, size_t block_size=128
, std::shared_ptr<OperationMode> ptr = nullptr) {
    this->block_size = block_size / 8;
    row_size = sqrt(this->block_size);
    col_size = row_size;
    s_box = new SBox();
    k_schedule = new KeySchedule(key, 
        this->block_size, s_box);
    o_mode = ptr != nullptr? ptr:
     std::make_shared<ECB>();
}

void AES::AES::sub_bytes(uint8_t* state, bool reverse=false) const {
    for (size_t i = 0; i < block_size; i++){
        uint8_t x = state[i];
        state[i] = reverse? 
            s_box->inv(x):
            s_box->sub(x);     
    }
}

template<typename T>
void shift_array(T* array, size_t amount, size_t size) {
    if (amount == 0) return;
    amount = amount % size;
    if (amount < 0)
        amount = size - amount;
    static T* tmp_row = nullptr;
    static size_t tmp_row_size = 0;
    if (tmp_row != nullptr
    && tmp_row_size < size)
        delete[] tmp_row;
    tmp_row = new T[size];
    const size_t sz = sizeof(T);
    memset(tmp_row, 0, size * sz);
    memcpy(tmp_row, array + amount, (size - amount) * sz);
    memcpy(tmp_row + (size - amount), array, amount * sz);
    memcpy(array, tmp_row, size * sz);
}

void AES::AES::shift_rows(uint8_t* state, bool reverse=false) const {
    for (size_t i = 1; i < col_size; i++)
        shift_array(state + i * row_size, 
            reverse? -i:i, row_size);
}

void AES::AES::mix_col(uint8_t*& state, bool reverse=false) const {
    uint8_t* result = new uint8_t[block_size];
    memset(result, 0, block_size);
    const uint8_t* matrix = reverse?
        u_mix_col_m: mix_col_m;
    for (size_t c = 0; c < col_size; c++)
        for (size_t i = 0; i < col_size; i++)
            for (size_t j = 0; j < row_size; j++)
                result[c * row_size + i] ^= g_mult(
                    matrix[i * row_size + j],
                    state[c * row_size + j]
                );
    memcpy(state, result, block_size);
    delete[] result;
}

void AES::AES::add_round_key(uint8_t* state, size_t idx) const {
    aes_key sub_key = k_schedule->get_round_key(idx);
    for (size_t i = 0; i < block_size; i++)
        state[i] ^= sub_key[i];
}

AES::AES::~AES(){
    if (k_schedule != nullptr)
        delete k_schedule;
    if (s_box != nullptr)
        delete s_box;
}

void AES::AES::encrypt_block(uint8_t* state) const{
    add_round_key(state, 0);
    size_t n_rounds = get_num_rounds();
    for (size_t i = 1; i < n_rounds; i++) {
        sub_bytes(state);
        shift_rows(state);
        if (i < n_rounds - 1)
            mix_col(state);
        add_round_key(state, i);
    }
}

void AES::AES::decrypt_block(uint8_t* state) const{
    size_t n_rounds = get_num_rounds();
    for (size_t i = n_rounds-1; i >= 1; i--) {
        add_round_key(state, i);
        if (i < n_rounds - 1)
            mix_col(state, true);
        shift_rows(state, true);
        sub_bytes(state, true);
    }
    add_round_key(state, 0);
}

uint8_t* pad_array(const uint8_t* src, 
size_t size, size_t block_size, 
size_t* padded_size = nullptr, 
size_t* padded_size_in_blocks = nullptr, 
uint8_t pad_char = 0, size_t extra_pad = 0) {
    size_t real_size = size;
    size_t int_block_sz =
         size/block_size;
    if (size % block_size)
        real_size = 
        (int_block_sz+1)
             * block_size;
    auto res = new uint8_t[real_size+extra_pad];
    memset(res, pad_char, real_size);
    memcpy(res, src, size);
    if (padded_size_in_blocks != nullptr) 
        *padded_size_in_blocks = real_size/block_size;
    if (padded_size != nullptr) 
        *padded_size = real_size+extra_pad;
    return res;
}

std::string pad_string(std::string s, size_t block_size, size_t *quot){
    size_t size = s.length();
    std::string res = s;
    size_t rem = size % block_size;
    if (rem) {
        size_t diff = block_size - rem;
        res += std::string(diff, '/');
    }
    *quot = res.length()/block_size;
    return res;
}

size_t AES::OperationMode::get_block_size
(const BlockEncryption* prn) const {
    return prn->block_size;
}

void AES::OperationMode::encrypt_block
(const BlockEncryption* prn, uint8_t* block)
 const { prn->encrypt_block(block);}

void AES::OperationMode::decrypt_block
(const BlockEncryption* prn, uint8_t* block)
 const { prn->decrypt_block(block);}

std::string AES::ECB::encrypted(const BlockEncryption* prn, std::string m) const {
    size_t block_size = get_block_size(prn);
    size_t int_block_sz = m.length()/block_size;
    auto res = pad_string(m, block_size, &int_block_sz);
    for (size_t i = 0; i < int_block_sz; i++)
        encrypt_block(prn, (uint8_t*)res.data()+i*16);
    res += res.length() - m.length();
    return res;
}

std::string AES::ECB::decrypted(const BlockEncryption* prn, std::string c) const{
    size_t block_size = get_block_size(prn);
    size_t int_block_sz = c.length() / block_size;
    size_t pad = c.back();
    c = c.substr(0, c.length() - 1);
    auto res = pad_string(c, block_size, &int_block_sz);
    for (size_t i = 0; i < int_block_sz; i++)
        decrypt_block(prn, (uint8_t*)res.data()+i*16);
    return pad? res.substr(0, res.length() - pad): res;
}

std::string AES::BlockEncryption::encrypted(std::string m) const
{ return o_mode!=nullptr? o_mode->encrypted(this,m) : m; }
std::string AES::BlockEncryption::decrypted(std::string c) const
{ return o_mode!=nullptr? o_mode->decrypted(this,c) : c; }

const uint8_t AES::AES::mix_col_m[16] = 
{
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
};
const uint8_t AES::AES::u_mix_col_m[16] = 
{
    0x0E, 0x0B, 0x0D, 0x09,
    0x09, 0x0E, 0x0B, 0x0D,
    0x0D, 0x09, 0x0E, 0x0B,
    0x0B, 0x0D, 0x09, 0x0E
};

#ifdef __AES_X_DBG_FLG__
    void AES::SBox::debug_print(int idt) const{
        std::string ident('\t', idt);
        std::cout<<ident<<"AESSBox {"<<std::endl;
        std::cout<<std::hex;
        std::cout<<ident<<"\t Forward SBox: [";
        for(int i = 0; i < 256; i++)
            std::cout<<std::setfill('0')<<std::setw(2)<<(int)s_box[i]<<" ";
        std::cout<<"]"<<std::endl;
        std::cout<<ident<<"\t Inverse SBox: [";
        for(int i = 0; i < 256; i++)
            std::cout<<std::setfill('0')<<std::setw(2)<<(int)s_inv[i]<<" ";
        std::cout<<"]"<<std::endl;
        std::cout<<ident<<"}"<<std::endl;
    }

    void AES::BaseKeySchedule::debug_print(int idt) const{
        std::string ident('\t', idt);
        std::cout<<ident<<"AESKeySchedule {"<<std::endl;
        std::cout<<std::hex<<std::setfill('0')<<std::setw(2);
        std::cout<<ident<<"\t Key: [";
        for(int i = 0; i < key.size(); i++)
            std::cout<<std::setfill('0')<<std::setw(2)<<(int)key[i]<<" ";
        std::cout<<"]"<<std::endl;
        std::cout<<ident<<"}"<<std::endl;
    }


    void AES::KeySchedule::debug_print(int idt) const{
        BaseKeySchedule::debug_print(idt);
    }

    void AES::AES::debug_print(int idt) const{
        std::string ident('\t', idt);
        std::cout<<ident<<"AESCrypt {"<<std::endl;
        s_box->debug_print(idt+1);
        k_schedule->debug_print(idt+1);
        std::cout<<ident<<"}"<<std::endl;
    }
#endif