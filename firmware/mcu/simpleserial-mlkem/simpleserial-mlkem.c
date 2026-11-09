/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "mlkem-independant.h"
#include "hal.h"
#include "simpleserial.h"
#include "params.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//Declareation
static uint8_t seed_d[32] = {0}, seed_z[32] = {0}, seed_m[32] = {0};
static uint8_t pk[800], sk[1632], ct[768], ss[32], coins[64] = {0}; //pk: public key, sk: secret key, ct: ciphertext, ss: shared secret, coins: randomness for keypair generation

//seed d is used for the randomness in the keypair generation
uint8_t get_seed_d(uint8_t* s, uint8_t len) 
{
    memcpy(seed_d, s, 32);  //memory copy the received seed into the seed_d array
    return 0x00;
}
//seed z is used for the randomness in the keypair generation
uint8_t get_seed_z(uint8_t* s, uint8_t len) 
{
    memcpy(seed_z, s, 32); //memory copy the received seed into the seed_z array
    return 0x00;
}
//seed m is used for the randomness in the encapsulation
uint8_t get_seed_m(uint8_t* s, uint8_t len) 
{
    memcpy(seed_m, s, 32); //memory copy the received seed into the seed_m array
    return 0x00;
}

uint8_t send_public_key(uint8_t* data, uint8_t len) //800 byte
{
    uint32_t chunk_idx = data[0]; 
    uint32_t offset = chunk_idx * 64; // set the starting position to read from the pk array
    
    
    if (offset >= 800) {
        return 0x01; 
    }
    uint32_t send_len = 64;
    
    if (800 - offset < 64) {
        send_len = 800 - offset;
    }
    
    // Send that chunk with tag 'r'
    simpleserial_put('r', send_len, pk + offset);
    return 0x00;
}

uint8_t send_private_key(uint8_t* data, uint8_t len)
{
    uint32_t chunk_idx = data[0]; 
    uint32_t offset = chunk_idx * 64; // Set the starting position to read from the sk array
    

    if (offset >= 1632) {
        return 0x01; 
    }
    
    uint32_t send_len = 64;
    //send last chunk with 32 bytes
    if (1632 - offset < 64) {
        send_len = 1632 - offset;
    }

    
    simpleserial_put('r', send_len, sk + offset);
    
    return 0x00;
}

uint8_t get_keypair(uint8_t* data, uint8_t len)
{
    // Copy the seeds into one array for keypair generation
    // The first 32 bytes are from seed_d, the next 32 bytes are from seed_z
    memcpy(coins, seed_d, 32);
    memcpy(coins + 32, seed_z, 32);
    trigger_high();

    mlkem_keypair(pk, sk, coins);

    trigger_low();
    return 0x00;
}

uint8_t get_encaps(uint8_t* data, uint8_t len)
{
    trigger_high();

    mlkem_enc(ct, ss, pk, seed_m);

    trigger_low();
    simpleserial_put('r', 32, ss);
    return 0x00;
}

uint8_t get_decaps(uint8_t* data, uint8_t len)
{
    trigger_high();

    mlkem_dec(ss, ct, sk);

    trigger_low();
    simpleserial_put('r', 32, ss);
    return 0x00;
}

uint8_t run_all_operations(uint8_t* data, uint8_t len)
{
    memcpy(coins, seed_d, 32);
    memcpy(coins + 32, seed_z, 32);
    //trigger_low();
    mlkem_keypair(pk, sk, coins);
    //delay(0.5);
    mlkem_enc(ct, ss, pk, seed_m);
    trigger_high();
    //trigger_low();
    mlkem_dec(ss, ct, sk);
    trigger_low();
    //trigger_high();
    simpleserial_put('r', 32, ss);
    return 0x00;
}

uint8_t static_set_pk(uint8_t* data, uint8_t len)
{
    uint32_t chunk_idx = data[0]; 
    uint32_t offset = chunk_idx * 50; // Set the starting position to read from the sk array
    

    if (offset >= 800) {
        return 0x01; 
    }
    
    uint32_t send_len = 50;
    //send last chunk with 50 bytes
    if (800 - offset < 50) {
        send_len = 800 - offset;
    }

    simpleserial_put('r', send_len, sk + offset);
    
    return 0x00;
}
uint8_t static_set_sk(uint8_t* data, uint8_t len)
{
    memcpy(sk, data, 1632);
    return 0x00;
}
uint8_t static_set_ss(uint8_t* data, uint8_t len)
{
    memcpy(ss, data, 32);
    return 0x00;
}
uint8_t static_set_ct(uint8_t* data, uint8_t len)
{
    memcpy(ct, data, 768);
    return 0x00;
}

uint8_t target_decapsulation(uint8_t* data, uint8_t len) {

    // pass ciphertext of choosing to mlkem_dec()
    trigger_high();
    mlkem_dec(ss, ct, sk);
    trigger_low();
    // verification
    simpleserial_put('r', 32, ss);
    return 0x00;
}

int main(void)
{
	

    platform_init();
    init_uart();
    trigger_setup();


    /* Uncomment this to get a HELLO message for debug */

    // putch('h');
    // putch('e');
    // putch('l');
    // putch('l');
    // putch('o');
    // putch('\n');

	simpleserial_init();
    simpleserial_addcmd('d', 32, get_seed_d);
    simpleserial_addcmd('z', 32, get_seed_z);
    simpleserial_addcmd('m', 32, get_seed_m);
    simpleserial_addcmd('k', 0, get_keypair);
    //simpleserial_addcmd('p', 1, send_public_key);
    //simpleserial_addcmd('v', 1, send_private_key);
    simpleserial_addcmd('e', 0, get_encaps);
    simpleserial_addcmd('c', 0, get_decaps);
    simpleserial_addcmd('a', 0, run_all_operations);

    simpleserial_addcmd('f', 800, static_set_pk);
    simpleserial_addcmd('g', 1632, static_set_sk);
    simpleserial_addcmd('h', 32, static_set_ss);
    simpleserial_addcmd('i', 768, static_set_ct);
    simpleserial_addcmd('t', 0, target_decapsulation);

    
    while(1)
        simpleserial_get();
}
