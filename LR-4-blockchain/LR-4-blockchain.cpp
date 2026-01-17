
// Прототип блокчейн-системы: цепочка блоков + подтверждение истории (валидация)
// Дополнительно: SHA-256 + Proof-of-Work (майнинг по сложности)
// C++17

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdint>
#include <stdexcept>


// SHA-256

namespace sha256_min {

    static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    static const uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    struct SHA256 {
        uint32_t h[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
        };

        std::vector<uint8_t> buffer;
        uint64_t totalLen = 0;

        void update(const uint8_t* data, size_t len) {
            totalLen += len;
            buffer.insert(buffer.end(), data, data + len);
            while (buffer.size() >= 64) {
                transform(buffer.data());
                buffer.erase(buffer.begin(), buffer.begin() + 64);
            }
        }

        void update(const std::string& s) {
            update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        }

        void transform(const uint8_t block[64]) {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (uint32_t(block[i * 4]) << 24) |
                    (uint32_t(block[i * 4 + 1]) << 16) |
                    (uint32_t(block[i * 4 + 2]) << 8) |
                    (uint32_t(block[i * 4 + 3]));
            }
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;

                hh = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }

        std::string finalHex() {
            // дополнение сообщения
            uint64_t bitLen = totalLen * 8;

            buffer.push_back(0x80);
            while ((buffer.size() % 64) != 56) buffer.push_back(0x00);

            for (int i = 7; i >= 0; --i) buffer.push_back(uint8_t((bitLen >> (i * 8)) & 0xff));

            
            for (size_t i = 0; i < buffer.size(); i += 64) transform(&buffer[i]);

            std::ostringstream oss;
            for (int i = 0; i < 8; ++i) {
                oss << std::hex << std::setw(8) << std::setfill('0') << h[i];
            }
            return oss.str();
        }
    };

    static inline std::string sha256(const std::string& s) {
        SHA256 ctx;
        ctx.update(s);
        return ctx.finalHex();
    }

} 


// Прототип блокчейна

static inline long long unixTimeNow() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

struct Block {
    int index = 0; //порядковый номер блока
    long long timestamp = 0; //время создания блока
    std::string data;       //полезные данные блока
    std::string previousHash;   //хеш предыдущего блока
    uint64_t nonce = 0; //значение для алгоритма Proof-of-Work
    std::string hash;   //хеш текущего блока.

    Block(int idx, std::string d, std::string prev)
        : index(idx), timestamp(unixTimeNow()), data(std::move(d)), previousHash(std::move(prev)) {
    }

    std::string calculateHash() const {
        std::ostringstream oss;
        oss << index << "|" << timestamp << "|" << data << "|" << previousHash << "|" << nonce;
        return sha256_min::sha256(oss.str());
    }

    void mine(int difficulty) {
        if (difficulty < 0) throw std::runtime_error("difficulty must be >= 0");
        std::string target(difficulty, '0');

        nonce = 0;
        do {
            ++nonce;
            hash = calculateHash();
        } while (hash.substr(0, target.size()) != target);
    }
};

class Blockchain {
public:
    explicit Blockchain(int difficulty = 3) : difficulty_(difficulty) {
        // Генезис-блок
        Block genesis(0, "Genesis block", "0");
        genesis.mine(difficulty_);
        chain_.push_back(genesis);
    }

    void addBlock(const std::string& data) {
        const Block& last = chain_.back();
        Block newBlock((int)chain_.size(), data, last.hash);
        newBlock.mine(difficulty_);
        chain_.push_back(newBlock);
    }

    bool isValid() const {
        if (chain_.empty()) return false;

        std::string target(difficulty_, '0');

        for (size_t i = 0; i < chain_.size(); ++i) {
            const Block& cur = chain_[i];

            // 1) hash должен соответствовать содержимому блока
            if (cur.hash != cur.calculateHash()) return false;

            // 2) hash должен соответствовать сложности (если майнинг включён)
            if (difficulty_ > 0 && cur.hash.substr(0, target.size()) != target) return false;

            // 3) связь с предыдущим блоком
            if (i == 0) {
                if (cur.previousHash != "0") return false; // генезис
            }
            else {
                const Block& prev = chain_[i - 1];
                if (cur.previousHash != prev.hash) return false;
            }
        }
        return true;
    }

    void print() const {
        for (const auto& b : chain_) {
            std::cout << "----- Block #" << b.index << " -----\n";
            std::cout << "Time:    " << b.timestamp << "\n";
            std::cout << "Data:    " << b.data << "\n";
            std::cout << "PrevHash:" << b.previousHash << "\n";
            std::cout << "Nonce:   " << b.nonce << "\n";
            std::cout << "Hash:    " << b.hash << "\n\n";
        }
    }

    // Для демонстрации "подтверждения истории": поменяем данные в уже созданном блоке
    // (после этого цепочка должна стать невалидной)
    void tamperData(size_t index, const std::string& newData) {
        if (index >= chain_.size()) throw std::out_of_range("bad index");
        chain_[index].data = newData;
        // намеренно НЕ пересчитываем hash / НЕ перемайним — показываем нарушение истории
    }

private:
    int difficulty_ = 3;
    std::vector<Block> chain_;
};


// Demo

int main() {
    // Сложность майнинга: 3 => hash должен начинаться с "000"
    Blockchain bc(3);

    bc.addBlock("Alice -> Bob: 10 coins");
    bc.addBlock("Bob -> Charlie: 4 coins");
    bc.addBlock("Charlie -> Dave: 1 coin");

    std::cout << "Blockchain created.\n";
    std::cout << "Valid? " << (bc.isValid() ? "YES" : "NO") << "\n\n";

    bc.print();

    // Демонстрация "подтверждения истории": изменим данные в блоке №1
    std::cout << "Tampering block #1 data...\n";
    bc.tamperData(1, "Alice -> Bob: 1000 coins (HACKED)");

    std::cout << "Valid after tamper? " << (bc.isValid() ? "YES" : "NO") << "\n";

    return 0;
}
