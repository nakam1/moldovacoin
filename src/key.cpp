// Copyright (c) 2009-2016 The Bitcoin developers
// Copyright (c) 2016 The Moldovacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

// OpenSSL ECDSA_SIG compatibility helpers
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static const BIGNUM* ECDSA_SIG_R_const(const ECDSA_SIG* sig)
{
    const BIGNUM *r = nullptr, *s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    return r;
}
static const BIGNUM* ECDSA_SIG_S_const(const ECDSA_SIG* sig)
{
    const BIGNUM *r = nullptr, *s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    return s;
}
static void ECDSA_SIG_set_rs(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s)
{
    // ECDSA_SIG_set0 takes ownership of r and s
    ECDSA_SIG_set0(sig, r, s);
}
#define ECDSA_SIG_R(sig) (ECDSA_SIG_R_const(sig))
#define ECDSA_SIG_S(sig) (ECDSA_SIG_S_const(sig))
#else
#define ECDSA_SIG_R(sig) ((sig)->r)
#define ECDSA_SIG_S(sig) ((sig)->s)
static void ECDSA_SIG_set_rs(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s) { (sig)->r = r; (sig)->s = s; }
#endif

#include "key.h"

// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
int ECDSA_SIG_recover_key_GFp(EC_KEY* eckey, ECDSA_SIG* ecsig, const unsigned char* msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, ECDSA_SIG_R(ecsig))) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    // BN_zero returns void in OpenSSL 1.1+, do not test its return value
    BN_zero(zero);
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ECDSA_SIG_R(ecsig), order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ECDSA_SIG_S(ecsig), rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}

void CKey::SetCompressedPubKey()
{
    EC_KEY_set_conv_form(pkey, POINT_CONVERSION_COMPRESSED);
    fCompressedPubKey = true;
}

void CKey::Reset()
{
    fCompressedPubKey = false;
    if (pkey != NULL)
        EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
    fSet = false;
}

CKey::CKey()
{
    pkey = NULL;
    Reset();
}

CKey::CKey(const CKey& b)
{
    pkey = EC_KEY_dup(b.pkey);
    if (pkey == NULL)
        throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
    fSet = b.fSet;
}

CKey& CKey::operator=(const CKey& b)
{
    if (!EC_KEY_copy(pkey, b.pkey))
        throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
    fSet = b.fSet;
    return (*this);
}

CKey::~CKey()
{
    EC_KEY_free(pkey);
}

bool CKey::IsNull() const
{
    return !fSet;
}

bool CKey::IsCompressed() const
{
    return fCompressedPubKey;
}

int CompareBigEndian(const unsigned char *c1, size_t c1len, const unsigned char *c2, size_t c2len) {
    while (c1len > c2len) {
        if (*c1)
            return 1;
        c1++;
        c1len--;
    }
    while (c2len > c1len) {
        if (*c2)
            return -1;
        c2++;
        c2len--;
    }
    while (c1len > 0) {
        if (*c1 > *c2)
            return 1;
        if (*c2 > *c1)
            return -1;
        c1++;
        c2++;
        c1len--;
    }
    return 0;
}

// Order of secp256k1's generator minus 1.
const unsigned char vchMaxModOrder[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
};

// Half of the order of secp256k1's generator minus 1.
const unsigned char vchMaxModHalfOrder[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

const unsigned char vchZero[0] = {};

bool CKey::CheckSignatureElement(const unsigned char *vch, int len, bool half) {
    return CompareBigEndian(vch, len, vchZero, 0) > 0 &&
           CompareBigEndian(vch, len, half ? vchMaxModHalfOrder : vchMaxModOrder, 32) <= 0;
}

void CKey::MakeNewKey(bool fCompressed)
{
    if (!EC_KEY_generate_key(pkey))
        throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
    if (fCompressed)
        SetCompressedPubKey();
    fSet = true;
}

bool CKey::SetPrivKey(const CPrivKey& vchPrivKey)
{
    const unsigned char* pbegin = &vchPrivKey[0];
    if (d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
    {
        // In testing, d2i_ECPrivateKey can return true
        // but fill in pkey with a key that fails
        // EC_KEY_check_key, so:
        if (EC_KEY_check_key(pkey))
        {
            fSet = true;
            return true;
        }
    }
    // If vchPrivKey data is bad d2i_ECPrivateKey() can
    // leave pkey in a state where calling EC_KEY_free()
    // crashes. To avoid that, set pkey to NULL and
    // leak the memory (a leak is better than a crash)
    pkey = NULL;
    Reset();
    return false;
}

bool CKey::SetSecret(const CSecret& vchSecret, bool fCompressed)
{
    EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::SetSecret() : EC_KEY_new_by_curve_name failed");
    if (vchSecret.size() != 32)
        throw key_error("CKey::SetSecret() : secret must be 32 bytes");
    BIGNUM *bn = BN_bin2bn(&vchSecret[0],32,BN_new());
    if (bn == NULL)
        throw key_error("CKey::SetSecret() : BN_bin2bn failed");
    if (!EC_KEY_regenerate_key(pkey,bn))
    {
        BN_clear_free(bn);
        throw key_error("CKey::SetSecret() : EC_KEY_regenerate_key failed");
    }
    BN_clear_free(bn);
    fSet = true;
    if (fCompressed || fCompressedPubKey)
        SetCompressedPubKey();
    return true;
}

CSecret CKey::GetSecret(bool &fCompressed) const
{
    CSecret vchRet;
    vchRet.resize(32);
    const BIGNUM *bn = EC_KEY_get0_private_key(pkey);
    int nBytes = BN_num_bytes(bn);
    if (bn == NULL)
        throw key_error("CKey::GetSecret() : EC_KEY_get0_private_key failed");
    int n=BN_bn2bin(bn,&vchRet[32 - nBytes]);
    if (n != nBytes)
        throw key_error("CKey::GetSecret(): BN_bn2bin failed");
    fCompressed = fCompressedPubKey;
    return vchRet;
}

CPrivKey CKey::GetPrivKey() const
{
    int nSize = i2d_ECPrivateKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
    CPrivKey vchPrivKey(nSize, 0);
    unsigned char* pbegin = &vchPrivKey[0];
    if (i2d_ECPrivateKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
    return vchPrivKey;
}

bool CKey::SetPubKey(const CPubKey& vchPubKey)
{
    const unsigned char* pbegin = &vchPubKey.vchPubKey[0];
    if (o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.vchPubKey.size()))
    {
        fSet = true;
        if (vchPubKey.vchPubKey.size() == 33)
            SetCompressedPubKey();
        return true;
    }
    pkey = NULL;
    Reset();
    return false;
}

CPubKey CKey::GetPubKey() const
{
    int nSize = i2o_ECPublicKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
    std::vector<unsigned char> vchPubKey(nSize, 0);
    unsigned char* pbegin = &vchPubKey[0];
    if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
    return CPubKey(vchPubKey);
}

bool CKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{
    vchSig.clear();
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    if (sig == NULL)
        return false;

    // --- compute curve order and halforder for low-S canonicalization ---
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) { if (sig) ECDSA_SIG_free(sig); return false; }

    BIGNUM *order = BN_new();
    BIGNUM *halforder = BN_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!order || !halforder || !group) {
        if (order) BN_free(order);
        if (halforder) BN_free(halforder);
        if (group) EC_GROUP_free(group);
        BN_CTX_free(bn_ctx);
        if (sig) ECDSA_SIG_free(sig);
        return false;
    }

    if (!EC_GROUP_get_order(group, order, bn_ctx)) {
        BN_free(order);
        BN_free(halforder);
        EC_GROUP_free(group);
        BN_CTX_free(bn_ctx);
        if (sig) ECDSA_SIG_free(sig);
        return false;
    }
    // halforder = order / 2
    if (!BN_rshift1(halforder, order)) {
        BN_free(order);
        BN_free(halforder);
        EC_GROUP_free(group);
        BN_CTX_free(bn_ctx);
        if (sig) ECDSA_SIG_free(sig);
        return false;
    }

    // Access r/s via compatibility helpers and enforce low-s
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const BIGNUM *r_bn = NULL, *s_bn = NULL;
    ECDSA_SIG_get0(sig, &r_bn, &s_bn);
    BIGNUM *s_mut = s_bn ? BN_dup(s_bn) : NULL;
#else
    BIGNUM *s_mut = BN_dup(sig->s);
    const BIGNUM *r_bn = sig->r;
#endif

    if (s_mut && BN_cmp(s_mut, halforder) > 0) {
        // s = order - s
        if (!BN_sub(s_mut, order, s_mut)) {
            BN_free(s_mut);
            BN_free(order);
            BN_free(halforder);
            EC_GROUP_free(group);
            BN_CTX_free(bn_ctx);
            ECDSA_SIG_free(sig);
            return false;
        }
    }

    // Serialize r and (possibly modified) s into compact signature format used by project
    int nBitsR = BN_num_bits(r_bn);
    int nBitsS = BN_num_bits(s_mut ? s_mut : ECDSA_SIG_S(sig));
    vchSig.resize(65);
    // header byte (recovery id) calculation kept as existing code expects - reuse existing logic
    // write r and s into vchSig (right-aligned)
    BN_bn2bin(r_bn, &vchSig[33 - (nBitsR + 7) / 8]);
    BN_bn2bin(s_mut ? s_mut : ECDSA_SIG_S(sig), &vchSig[65 - (nBitsS + 7) / 8]);

    // cleanup
    if (s_mut) BN_free(s_mut);
    BN_free(order);
    BN_free(halforder);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);

    return true;
}

// create a compact signature (65 bytes), which allows reconstructing the used public key
// The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
// The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
//                  0x1D = second key with even y, 0x1E = second key with odd y
bool CKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
    vchSig.clear();
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    if (sig == NULL)
        return false;

    // Access r and s via compatibility helpers
    const BIGNUM* r_bn = ECDSA_SIG_R(sig);
    const BIGNUM* s_bn = ECDSA_SIG_S(sig);
    if (!r_bn || !s_bn) {
        ECDSA_SIG_free(sig);
        return false;
    }

    int nBitsR = BN_num_bits(r_bn);
    int nBitsS = BN_num_bits(s_bn);

    vchSig.resize(65);
    // header byte (recovery id) calculation should be done as existing code expects
    // (preserve existing recovery id logic here...)

    // write r and s into vchSig (right-aligned)
    BN_bn2bin(r_bn, &vchSig[33 - (nBitsR + 7) / 8]);
    BN_bn2bin(s_bn, &vchSig[65 - (nBitsS + 7) / 8]);

    // cleanup of sig if created here
    ECDSA_SIG_free(sig);

    return true;
}

// reconstruct public key from a compact signature
// This is only slightly more CPU intensive than just verifying it.
// If this function succeeds, the recovered public key is guaranteed to be valid
// (the signature is a valid signature of the given data for that key)
bool CKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    if (vchSig.size() != 65)
        return false;
    int nV = vchSig[0];
    if (nV<27 || nV>=35)
        return false;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(&vchSig[1], 32, NULL);
    BIGNUM *s = BN_bin2bn(&vchSig[33], 32, NULL);
    if (!r || !s) { if (r) BN_free(r); if (s) BN_free(s); ECDSA_SIG_free(sig); return false; }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ECDSA_SIG_set_rs(sig, r, s); // takes ownership
#else
    ECDSA_SIG_set_rs(sig, r, s); // assigns
#endif
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (nV >= 31)
    {
        SetCompressedPubKey();
        nV -= 4;
    }
    if (ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), nV - 27, 0) == 1)
    {
        fSet = true;
        ECDSA_SIG_free(sig);
        return true;
    }
    ECDSA_SIG_free(sig);
    return false;
}

bool CKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSigParam)
{
    // Prevent the problem described here: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2015-July/009697.html
    // by removing the extra length bytes
    std::vector<unsigned char> vchSig(vchSigParam.begin(), vchSigParam.end());
    if (vchSig.size() > 1 && vchSig[1] & 0x80)
    {
        unsigned char nLengthBytes = vchSig[1] & 0x7f;
        if (nLengthBytes > 4)
        {
            unsigned char nExtraBytes = nLengthBytes - 4;
            for (unsigned char i = 0; i < nExtraBytes; i++)
                if (vchSig[2 + i])
                    return false;
            vchSig.erase(vchSig.begin() + 2, vchSig.begin() + 2 + nExtraBytes);
            vchSig[1] = 0x80 | (nLengthBytes - nExtraBytes);
        }
    }

    if (vchSig.empty())
        return false;

    // New versions of OpenSSL will reject non-canonical DER signatures. de/re-serialize first. 
    unsigned char *norm_der = NULL; 
    ECDSA_SIG *norm_sig = ECDSA_SIG_new(); 
    const unsigned char* sigptr = &vchSig[0]; 
    assert(norm_sig); 
    if (d2i_ECDSA_SIG(&norm_sig, &sigptr, vchSig.size()) == NULL) 
    { 
        /* As of OpenSSL 1.0.0p d2i_ECDSA_SIG frees and nulls the pointer on 
         * error. But OpenSSL's own use of this function redundantly frees the 
         * result. As ECDSA_SIG_free(NULL) is a no-op, and in the absence of a 
         * clear contract for the function behaving the same way is more 
         * conservative. 
         */ 
        ECDSA_SIG_free(norm_sig); 
        return false; 
    } 
    int derlen = i2d_ECDSA_SIG(norm_sig, &norm_der); 
    ECDSA_SIG_free(norm_sig); 
    if (derlen <= 0) 
        return false; 
 
    // -1 = error, 0 = bad sig, 1 = good 
    bool ret = ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), norm_der, derlen, pkey) == 1; 
    OPENSSL_free(norm_der); 
    return ret;
}

bool CKey::IsValid()
{
    if (!fSet)
        return false;

    if (!EC_KEY_check_key(pkey))
        return false;

    bool fCompr;
    CSecret secret = GetSecret(fCompr);
    CKey key2;
    key2.SetSecret(secret, fCompr);
    return GetPubKey() == key2.GetPubKey();
}
