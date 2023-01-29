#include "protocol.h"

#include <tweetnacl.h>
#include <randombytes.h>
#include <cstring>
#include "mbedtls/md.h"
#include "util.h"
#include <Logger.h>

int crcCCITT(unsigned char *data, int len) {
	unsigned short crc = 0xffff;
	for (int i = 0; i < len; i++) {
		unsigned short adj = data[i];
		crc ^= adj << 8;
		for (int j = 0; j < 8; j++) {
			if ((crc & 0x8000) > 0) {
				crc = (crc << 1) ^ 0x1021;
			} else {
				crc <<= 1;
			}
		}
	}
	return crc;
}

void calculate_keypair(unsigned char *public_key32, unsigned char *private_key32) {
    calculate_challenge(private_key32, 32);
    crypto_scalarmult_base(public_key32, private_key32);
}

void calculate_challenge(unsigned char *out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = random(256);
    }
}

void calculate_dh1(unsigned char *scalar32, unsigned char *point32, unsigned char *out32) {
    crypto_scalarmult_curve25519(scalar32, point32, out32);
}

void calculate_kdh1(unsigned char *in32, unsigned char *out32) {
    unsigned char _0[16];
    memset(&_0, 0, 16);
    unsigned char sigma[] = "expand 32-byte k";
    crypto_core_hsalsa20(out32, (unsigned char *)&_0, in32, (unsigned char *)&sigma);
}

void prepare_unencrypted(unsigned short cmd, unsigned char *data, int len, unsigned char *challenge32, unsigned char *out) {
    memcpy(out, &cmd, 2);
    int pointer = 2;
    if (challenge32 != NULL) {
        memcpy(&out[pointer], challenge32, 32);
        pointer += 32;
    }
    memcpy(&out[pointer], data, len);
    pointer += len;
    unsigned short crc = crcCCITT(out, pointer);
    memcpy(&out[pointer], &crc, 2);
}

void calculate_h1(unsigned char *shared_key32, unsigned char *in, int len, unsigned char *challenge32, unsigned char *out32) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    unsigned char *payload = (unsigned char *)malloc(len + 32);
    memcpy(payload, in, len);
    memcpy(&payload[len], challenge32, 32);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (unsigned char *)shared_key32, 32);
    mbedtls_md_hmac_update(&ctx, (unsigned char *)payload, 32 + len);
    mbedtls_md_hmac_finish(&ctx, out32);
    mbedtls_md_free(&ctx);
    free(payload);
}

void prepare_auth_authenticator(unsigned char *public_key132, unsigned char *public_key232, unsigned char *out64) {
  memcpy(out64, public_key132, 32);
  memcpy(&out64[32], public_key232, 32);
}

void prepare_auth_data(unsigned char type, unsigned int id, char *name, unsigned char *nonce32, unsigned char *out69) {
    out69[0] = type; // Bridge
    memcpy(&out69[1], &id, 4);
    memset(&out69[5], 0, 32);
    memcpy(&out69[5], name, strlen(name));
    memcpy(&out69[5 + 32], nonce32, 32);
}

void prepare_encrypted(unsigned char *key36, unsigned short cmd, unsigned char *payload, int len, unsigned char *nonce24, unsigned char *out) {
    unsigned char *buffer = (unsigned char *)malloc(4 + 2 + len + 2 + 32);
    memset(buffer, 0, 32);
    memcpy(&buffer[32], key36, 4);
    memcpy(&buffer[4 + 32], &cmd, 2);
    memcpy(&buffer[6 + 32], payload, len);
    unsigned short crc = crcCCITT(&buffer[32], len + 6);
    memcpy(&buffer[len + 6 + 32], &crc, 2);
    // log_bytes("prepare_encrypted()", "To be encrypted:", (char *)&buffer[32], 6 + len + 2);
    memcpy(out, nonce24, 24);
    memcpy(&out[24], key36, 4);
    int adata_len = 8 + len;
    unsigned short msg_len = 16 + adata_len;
    memcpy(&out[24 + 4], &msg_len, 2);
    // log_bytes("prepare_encrypted()", "Buffer:", (char *)buffer, 32 + 6 + len + 2);
    // log_bytes("prepare_encrypted()", "Out before encrypt:", (char *)out, 30);

    unsigned char *out_buffer = (unsigned char *)malloc(32 + adata_len);
    memset(out_buffer, 0, 32 + adata_len);
    // log_bytes("prepare_encrypted()", "Shared key:", (char *)&key36[4], 32);
    // log_bytes("prepare_encrypted()", "nonce:", (char *)nonce24, 24);
    crypto_secretbox(out_buffer, buffer, 32 + adata_len, nonce24, &key36[4]);
    // log_bytes("prepare_encrypted()", "Encrypted:", (char *)out_buffer, 32 + adata_len);
    memcpy(&out[30], &out_buffer[16], 16 + adata_len);
    free(out_buffer);
    free(buffer);
}

unsigned short get_encrypted_msg_len(unsigned char *encrypted) {
    unsigned short result;
    memcpy(&result, &encrypted[24 + 4], 2);
    return result - 16;
}

void decrypt_encrypted(unsigned char *shared_key36, unsigned char *encrypted, unsigned char *out) {
    auto msg_len = get_encrypted_msg_len(encrypted);
    auto buffer_len = 32 + msg_len;
    // Logger::verbose("decrypt_encrypted()", (String("Msg len: ")+msg_len).c_str());
    auto c_buffer = (unsigned char *)malloc(buffer_len);
    memset(c_buffer, 0, 16);
    memcpy(&c_buffer[16], &encrypted[30], msg_len + 16);
    // log_bytes("decrypt_encrypted()", "c_buffer:", (char *)c_buffer, buffer_len);

    auto m_buffer = (unsigned char *)malloc(buffer_len);
    // log_bytes("decrypt_encrypted()", "m_buffer:", (char *)m_buffer, buffer_len);
    // log_bytes("decrypt_encrypted()", "shared key:", (char *)&shared_key36[4], 32);
    // log_bytes("decrypt_encrypted()", "nonce:", (char *)encrypted, 24);
    auto result = crypto_secretbox_open(m_buffer, c_buffer, buffer_len, encrypted, &shared_key36[4]);
    // log_bytes("decrypt_encrypted()", "crypt.():", (char *)m_buffer, buffer_len);

    memcpy(out, &m_buffer[32], msg_len);

    free(c_buffer);
    free(m_buffer);
}

unsigned char check_error(unsigned short expected, unsigned char *in, int in_len) {
    if (in_len < 5) {
        return 0x01; // Invalid payload
    }
    unsigned short first;
    memcpy(&first, in, 2);
    if (first == CMD_ERROR_REPORT) {
        // Error report
        return (unsigned short)in[2];
    }
    if (first != expected) {
        return 0x02; // Unexpected command
    }
    return 0; // All good
}

void extract_unencrypted(unsigned char *data, unsigned char *out, int len) {
    memcpy(out, &data[2], len);
}

int decrypt_maybe(unsigned char *key36, unsigned char *in, int len, unsigned char *out256) {
    if (len < 0)
        return len;
    // log_bytes("decrypt_maybe()", "Will check:", (char *)in, len);
    if ((len > 28) && (memcmp(&in[24], key36, 4) == 0)) {
        // Encrypted - ID matches
        auto msg_len = get_encrypted_msg_len(in);
        // auto log = String("Encrypted message, len: ") + String(msg_len);
        // Logger::verbose("decrypt_maybe()", log.c_str());
        decrypt_encrypted(key36, in, out256);
        memcpy(out256, &out256[4], msg_len - 4);
        return msg_len - 4;
    }
    // Logger::verbose("decrypt_maybe()", "Looks like plain message");
    memcpy(out256, in, len);
    return len;
}
