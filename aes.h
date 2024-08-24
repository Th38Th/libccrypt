#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace AES {
    typedef std::vector<uint8_t> aes_key, byte_array;
    void generate_key(aes_key& dst);
    class SBox
    {
        const uint8_t* s_box = nullptr;
        const uint8_t* s_inv = nullptr;
        static uint8_t* gen_box(bool);
        public:
            #ifdef __AES_X_DBG_FLG__
                void debug_print(int) const;
            #endif
            SBox();
            uint8_t sub(uint8_t) const;
            uint8_t inv(uint8_t) const;
            ~SBox();
    };
    class BaseKeySchedule
    {
        size_t block_size;
        const SBox* s_box = nullptr;
        virtual const uint8_t* generate_rc();
        virtual const uint8_t* generate_w();
        virtual void get_rcon(size_t idx, uint8_t* dst);
        protected:
            aes_key key;
            const uint8_t* rc = nullptr;
            const uint8_t* w = nullptr;
            void rebuild();
            void rot_word(uint8_t*, size_t);
            void xor_word(uint8_t*, uint8_t*, size_t);
            void sub_word(uint8_t*, size_t);
            virtual size_t get_num_words() const;
        public:
            #ifdef __AES_X_DBG_FLG__
                virtual void debug_print(int) const;
            #endif
            BaseKeySchedule(const aes_key&, size_t, const SBox*);
            BaseKeySchedule(size_t, size_t, const SBox*);
            aes_key get_round_key(size_t idx) const;
            size_t get_key_length() const; 
            size_t get_num_rounds() const;
            virtual ~BaseKeySchedule();
    };
    class KeySchedule : public BaseKeySchedule
    {
        const uint8_t* generate_rc() override;
        const uint8_t* generate_w() override;
        void get_rcon(size_t idx, uint8_t* dst) override;
        size_t get_num_words() const override;
        public:
            #ifdef __AES_X_DBG_FLG__
                void debug_print(int) const;
            #endif
            KeySchedule(const aes_key&, size_t, const SBox*);
            KeySchedule(size_t, size_t, const SBox*);
            ~KeySchedule() override;
    };
    class BlockEncryption;
    class OperationMode
    {
        protected:
            size_t get_block_size(const BlockEncryption*) const;
            void encrypt_block(const BlockEncryption*,uint8_t*) const;
            void decrypt_block(const BlockEncryption*,uint8_t*) const;
        public:
            virtual std::string encrypted(const BlockEncryption*, std::string) const = 0;
            virtual std::string decrypted(const BlockEncryption*, std::string) const = 0;
    };
    class ECB : public OperationMode 
    {
        public:
            std::string encrypted(const BlockEncryption*, std::string) const override;
            std::string decrypted(const BlockEncryption*, std::string) const override;
    };
    class BlockEncryption {
        protected:
            size_t block_size;
            std::shared_ptr<OperationMode> o_mode;
            virtual void encrypt_block(uint8_t*) const = 0;
            virtual void decrypt_block(uint8_t*) const = 0;
        public:
            std::string encrypted(std::string) const;
            std::string decrypted(std::string) const;
            friend class OperationMode;
    };
    class AES : public BlockEncryption
    {
        size_t row_size;
        size_t col_size;
        const SBox* s_box = nullptr;
        const BaseKeySchedule* k_schedule;
        static const uint8_t mix_col_m[16];
        static const uint8_t u_mix_col_m[16];
        void sub_bytes(uint8_t*,bool) const;
        void shift_rows(uint8_t*,bool) const;
        void mix_col(uint8_t*&,bool) const;
        void add_round_key(uint8_t*,size_t) const;
        virtual void encrypt_block(uint8_t*) const;
        virtual void decrypt_block(uint8_t*) const;
        public:
            AES(size_t,size_t,std::shared_ptr<OperationMode>);
            AES(const aes_key&,size_t,std::shared_ptr<OperationMode>);
            #ifdef __AES_X_DBG_FLG__
                void debug_print(int) const;
            #endif
            size_t get_num_rounds() const;
            size_t get_key_size() const;
            ~AES();
    };
};