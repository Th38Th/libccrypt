#include "aes.h"
#include <vector>

#pragma once
typedef std::vector<uint8_t> byte_array;

namespace AES {
    class CBC: public OperationMode {
        byte_array iv;
        public:
            CBC(size_t);
            void init_random_iv(size_t);
            void set_iv(byte_array iv); byte_array get_iv();
            std::string encrypted(const BlockEncryption*, std::string) const override;
            std::string decrypted(const BlockEncryption*, std::string) const override;
    };
}