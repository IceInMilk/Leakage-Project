
#include <stdlib.h> 
#include "api.h"
#include "indcpa.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "mlkem-independant.h"
#include "verify.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>


int mlkem_keypair(uint8_t *pk, uint8_t *sk, uint8_t *fixed_coins) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk, sk, fixed_coins);
}

int mlkem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, uint8_t *fixed_coins) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, pk, fixed_coins);
}

int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
}
