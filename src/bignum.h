// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin developers
// Copyright (c) 2016 The Moldovacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <vector>
#include <string>
#include <stdint.h>
#include <algorithm>
#include <stdexcept>          // <-- added
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "serialize.h"

class uint256; // forward

class CBigNum
{
private:
    BIGNUM* bn;

    static BN_CTX* getBNCTX()
    {
        static BN_CTX* ctx = BN_CTX_new();
        return ctx;
    }

    BIGNUM* ensure()
    {
        if (!bn) bn = BN_new();
        return bn;
    }

public:
    // (removed duplicate forward-declarations; definitions appear later)
    CBigNum() : bn(BN_new()) {}
    CBigNum(const CBigNum& b) : bn(BN_new())
    {
        if (b.bn) BN_copy(bn, b.bn);
        else BN_zero(bn);
    }
    CBigNum& operator=(const CBigNum& b)
    {
        if (this == &b) return *this;
        if (!bn) bn = BN_new();
        if (b.bn) BN_copy(bn, b.bn);
        else BN_zero(bn);
        return *this;
    }
    ~CBigNum()
    {
        if (bn) BN_clear_free(bn);
        bn = nullptr;
    }

    explicit CBigNum(uint256 n);
    CBigNum(signed char n)        { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(short n)              { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int n)                { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(long n)               { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(long long n)          { bn = BN_new(); setint64(n); }
    CBigNum(unsigned char n)      { bn = BN_new(); setulong(n); }
    CBigNum(unsigned short n)     { bn = BN_new(); setulong(n); }
    CBigNum(unsigned int n)       { bn = BN_new(); setulong(n); }
    CBigNum(unsigned long n)      { bn = BN_new(); setulong(n); }
    CBigNum(unsigned long long n) { bn = BN_new(); setuint64(n); }
    explicit CBigNum(const std::vector<unsigned char>& vch) { bn = BN_new(); setvch(vch); }

    // Serialization helpers required by serialize.h
    template <typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        std::vector<unsigned char> vch = getvch();
        ::Serialize(s, vch, nType, nVersion); // ensure global Serialize is called
    }

    template <typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        std::vector<unsigned char> vch;
        ::Unserialize(s, vch, nType, nVersion); // ensure global Unserialize is called
        setvch(vch);
    }

    // Basic accessors / conversions
    int bitSize() const { return bn ? BN_num_bits(bn) : 0; }

    void setulong(unsigned long n)
    {
        ensure();
        BN_set_word(bn, n);
    }
    unsigned long getulong() const
    {
        return bn ? BN_get_word(bn) : 0;
    }
    unsigned int getuint() const { return (unsigned int)getulong(); }

    int getint() const
    {
        if (!bn) return 0;
        unsigned long n = BN_get_word(bn);
        return BN_is_negative(bn) ? -(int)n : (int)n;
    }

    void setint64(int64_t n)
    {
        unsigned char pch[8];
        uint64_t un = (n < 0) ? -uint64_t(n) : uint64_t(n);
        for (int i = 0; i < 8; ++i) pch[7 - i] = (unsigned char)(un >> (8*i));
        // strip leading zeros
        const unsigned char* p = pch;
        int len = 0;
        while (len < 8 && *p == 0) { ++p; ++len; }
        if (!bn) bn = BN_new();
        BN_mpi2bn(p, 8 - len, bn);
        if (n < 0) BN_set_negative(bn, 1);
    }

    uint64_t getuint64() const
    {
        if (!bn) return 0;
        int nSize = BN_bn2mpi(bn, NULL);
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(bn, vch.data());
        uint64_t result = 0;
        int start = std::max(0, (int)vch.size() - 8);
        for (int i = start; i < (int)vch.size(); ++i) result = (result << 8) | vch[i];
        return result;
    }

    void setuint64(uint64_t n)
    {
        unsigned char pch[8];
        for (int i = 0; i < 8; ++i) pch[7 - i] = (unsigned char)(n >> (8*i));
        if (!bn) bn = BN_new();
        BN_mpi2bn(pch, 8, bn);
    }

    void setuint256(uint256 n);
    uint256 getuint256() const;

    // Compact format (as used in nBits) helpers
    // SetCompact returns *this to allow expressions like CBigNum().SetCompact(nBits)
    CBigNum& SetCompact(unsigned int nCompact)
    {
        unsigned int nSize = nCompact >> 24;
        unsigned int nWord = nCompact & 0x007fffff;
        bool fNegative = (nCompact & 0x00800000) != 0;

        std::vector<unsigned char> vch;
        if (nSize <= 3) {
            // nWord >> 8*(3-nSize)
            nWord >>= 8 * (3 - nSize);
            for (int i = 0; i < 3 && (nWord > 0); ++i) {
                vch.insert(vch.begin(), (unsigned char)(nWord & 0xff));
                nWord >>= 8;
            }
        } else {
            vch.resize(nSize);
            vch[0] = (unsigned char)((nWord >> 16) & 0xff);
            vch[1] = (unsigned char)((nWord >> 8) & 0xff);
            vch[2] = (unsigned char)(nWord & 0xff);
            for (unsigned int i = 3; i < nSize; ++i) vch[i] = 0;
        }
        if (!bn) bn = BN_new();
        if (!vch.empty()) BN_mpi2bn(vch.data(), vch.size(), bn);
        else BN_zero(bn);
        if (fNegative) BN_set_negative(bn, 1);
        return *this;
    }

    unsigned int GetCompact() const
    {
        if (!bn) return 0;
        // produce compact representation: size + top 3 bytes as mantissa
        int nSize = BN_num_bytes(bn);
        std::vector<unsigned char> vch(nSize);
        if (nSize > 0) BN_bn2bin(bn, vch.data());
        unsigned int nCompact = 0;
        if (nSize <= 3) {
            unsigned int nWord = 0;
            for (int i = 0; i < nSize; ++i) nWord = (nWord << 8) | vch[i];
            nCompact = nWord << 8 * (3 - nSize);
        } else {
            nCompact = (vch[0] << 16) | (vch[1] << 8) | vch[2];
        }
        nCompact |= (nSize << 24);
        if (BN_is_negative(bn)) nCompact |= 0x00800000;
        return nCompact;
    }

    // divide by small integer (used by code expecting bn /= value)
    CBigNum& operator/=(long v)
    {
        if (!bn) { bn = BN_new(); BN_zero(bn); return *this; }
        if (v == 0) throw bignum_error("division by zero");
        BIGNUM* bv = BN_new();
        BN_set_word(bv, (unsigned long) (v < 0 ? -v : v));
        BIGNUM* rem = BN_new();
        if (!BN_div(bn, rem, bn, bv, getBNCTX())) {
            BN_free(bv); BN_free(rem);
            throw bignum_error("BN_div failed");
        }
        // sign handling
        if (v < 0) BN_set_negative(bn, !BN_is_negative(bn));
        BN_free(bv); BN_free(rem);
        return *this;
    }

    // arithmetic wrappers (use BN_* functions)
    friend CBigNum operator+(const CBigNum& a, const CBigNum& b)
    {
        CBigNum r;
        if (!BN_add(r.bn, a.bn, b.bn)) BN_zero(r.bn);
        return r;
    }
    friend CBigNum operator-(const CBigNum& a, const CBigNum& b)
    {
        CBigNum r;
        if (!BN_sub(r.bn, a.bn, b.bn)) BN_zero(r.bn);
        return r;
    }
    friend CBigNum operator*(const CBigNum& a, const CBigNum& b)
    {
        CBigNum r;
        if (!BN_mul(r.bn, a.bn, b.bn, getBNCTX())) BN_zero(r.bn);
        return r;
    }
    friend CBigNum operator/(const CBigNum& a, const CBigNum& b)
    {
        CBigNum r;
        if (!BN_div(r.bn, NULL, a.bn, b.bn, getBNCTX())) BN_zero(r.bn);
        return r;
    }
    friend CBigNum operator%(const CBigNum& a, const CBigNum& b)
    {
        CBigNum r;
        if (!BN_nnmod(r.bn, a.bn, b.bn, getBNCTX())) BN_zero(r.bn);
        return r;
    }

    CBigNum& operator+=(const CBigNum& b) { BN_add(bn, bn, b.bn); return *this; }
    CBigNum& operator-=(const CBigNum& b) { BN_sub(bn, bn, b.bn); return *this; }
    CBigNum& operator*=(const CBigNum& b) { BN_mul(bn, bn, b.bn, getBNCTX()); return *this; }

    CBigNum& operator<<=(unsigned int shift) { BN_lshift(bn, bn, shift); return *this; }
    CBigNum& operator>>=(unsigned int shift) { BN_rshift(bn, bn, shift); return *this; }

    CBigNum& operator++() { BN_add(bn, bn, BN_value_one()); return *this; }
    CBigNum& operator--() { CBigNum r; BN_sub(r.bn, bn, BN_value_one()); BN_copy(bn, r.bn); return *this; }

    bool isZero() const { return bn ? BN_is_zero(bn) : true; }
    bool isOne() const { return bn ? BN_is_one(bn) : false; }

    std::string ToString(int base=10) const
    {
        if (!bn) return "0";
        char* cstr = (base == 16) ? BN_bn2hex(bn) : BN_bn2dec(bn);
        std::string s = cstr ? std::string(cstr) : std::string();
        if (cstr) OPENSSL_free(cstr);
        return s;
    }

    // modular/arithmetic helpers
    CBigNum pow(const CBigNum& e) const
    {
        CBigNum ret;
        if (!BN_exp(ret.bn, bn, e.bn, getBNCTX())) BN_zero(ret.bn);
        return ret;
    }

    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const
    {
        CBigNum ret;
        if (!BN_mod_mul(ret.bn, bn, b.bn, m.bn, getBNCTX())) BN_zero(ret.bn);
        return ret;
    }

    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const
    {
        CBigNum ret;
        if (!BN_mod_exp(ret.bn, bn, e.bn, m.bn, getBNCTX())) BN_zero(ret.bn);
        return ret;
    }

    CBigNum inverse(const CBigNum& m) const
    {
        CBigNum ret;
        BIGNUM* r = BN_mod_inverse(NULL, bn, m.bn, getBNCTX());
        if (r) { BN_free(ret.bn); ret.bn = r; }
        else BN_zero(ret.bn);
        return ret;
    }

    static CBigNum randBignum(const CBigNum& range)
    {
        CBigNum ret;
        if (!BN_rand_range(ret.bn, range.bn)) BN_zero(ret.bn);
        return ret;
    }

    static CBigNum RandKPOSTigum(uint32_t k)
    {
        CBigNum ret;
        if (!BN_rand(ret.bn, k, -1, 0)) BN_zero(ret.bn);
        return ret;
    }

    static CBigNum generatePrime(unsigned int numBits, bool safe=false)
    {
        CBigNum ret;
        if (!BN_generate_prime_ex(ret.bn, numBits, safe ? 1 : 0, NULL, NULL, NULL)) BN_zero(ret.bn);
        return ret;
    }

    CBigNum gcd(const CBigNum& b) const
    {
        CBigNum ret;
        if (!BN_gcd(ret.bn, bn, b.bn, getBNCTX())) BN_zero(ret.bn);
        return ret;
    }

    bool isPrime(int checks=0) const
    {
        BN_CTX* pctx = getBNCTX();
        int ret = BN_is_prime(bn, checks, NULL, pctx, NULL);
        return ret == 1;
    }

    // expose internal pointer
    const BIGNUM* getBIGNUM() const { return bn; }
    BIGNUM*& getBIGNUM() { return bn; }
};

// Non-member helpers so expressions like (bn << 8) | byte work
inline CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r(a);
    if (r.getBIGNUM()) BN_lshift(r.getBIGNUM(), r.getBIGNUM(), shift);
    return r;
}

// Treat '|' with small integer operand as add (used in base58 byte-append: (bn<<8)|byte)
inline CBigNum operator|(const CBigNum& a, unsigned long w)
{
    CBigNum r(a);
    if (!r.getBIGNUM()) r.getBIGNUM() = BN_new(); // ensure allocated (rare)
    if (!BN_add_word(r.getBIGNUM(), w)) BN_zero(r.getBIGNUM());
    return r;
}

// Right-shift operator
inline CBigNum operator>>(const CBigNum& a, unsigned int shift)
{
    CBigNum r(a);
    if (r.getBIGNUM()) BN_rshift(r.getBIGNUM(), r.getBIGNUM(), shift);
    return r;
}

// Unary minus (negation)
inline CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);
    if (!r.getBIGNUM()) r.getBIGNUM() = BN_new();
    // flip sign
    BN_set_negative(r.getBIGNUM(), !BN_is_negative(a.getBIGNUM()));
    return r;
}

// Add a small exception type used by older code (e.g. base58.h)
class bignum_error : public std::runtime_error {
public:
    explicit bignum_error(const std::string& msg) : std::runtime_error(msg) {}
};

// RAII helper for BN_CTX used by older code (CAutoBN_CTX)
class CAutoBN_CTX
{
private:
    BN_CTX* pctx;
public:
    CAutoBN_CTX() : pctx(BN_CTX_new()) {}
    ~CAutoBN_CTX() { if (pctx) BN_CTX_free(pctx); }
    operator BN_CTX*() const { return pctx; }
    BN_CTX* operator->() const { return pctx; }
};

// comparisons using BN_cmp
inline bool operator==(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.getBIGNUM(), b.getBIGNUM()) == 0; }
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.getBIGNUM(), b.getBIGNUM()) != 0; }
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return BN_cmp(a.getBIGNUM(), b.getBIGNUM()) < 0; }
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return BN_cmp(a.getBIGNUM(), b.getBIGNUM()) > 0; }
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.getBIGNUM(), b.getBIGNUM()) <= 0; }
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return BN_cmp(a.getBIGNUM(), b.getBIGNUM()) >= 0; }

#endif // BITCOIN_BIGNUM_H
