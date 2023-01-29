#ifndef PROTOCOL_H
#define PROTOCOL_H

#define CMD_NOTHING 0x0000
#define CMD_REQUEST_DATA 0x0001
#define CMD_PUBLIC_KEY 0x0003
#define CMD_CHALLENGE 0x0004
#define CMD_AUTH_AUTHENTICATOR 0x0005
#define CMD_AUTH_DATA 0x0006
#define CMD_AUTH_ID 0x0007
#define CMD_REQUEST_AUTHORIZATIONS 0x0009
#define CMD_AUTHORIZATION 0x000A
#define CMD_STATE 0x000C
#define CMD_LOCK_ACTION 0x000D
#define CMD_STATUS 0x000E
#define CMD_ERROR_REPORT 0x0012
#define CMD_SET_CONFIG 0x0013
#define CMD_REQUEST_CONFIG 0x0014
#define CMD_CONFIG 0x0015
#define CMD_AUTH_ID_CONFIRMATION 0x001E
#define CMD_AUTHORIZATIONS_COUNT 0x0027
#define CMD_REQUEST_KEYPAD_CODES 0x0043
#define CMD_KEYPAD_CODE_COUNT 0x0044
#define CMD_KEYPAD_CODE 0x0045
#define CMD_UPDATE_KEYPAD_CODE 0x0046
#define CMD_REQUEST_LOG_ENTRIES 0x0031
#define CMD_LOG_ENTRY 0x0032
#define CMD_LOG_ENTRIES_COUNT 0x0033

#define ENCRYPTED_BUFFER_SIZE 54 // 30 + 24

void prepare_unencrypted(unsigned short cmd, unsigned char *data, int len, unsigned char *challenge32, unsigned char *out);
void extract_unencrypted(unsigned char *data, unsigned char *out, int len);

void calculate_keypair(unsigned char *public_key32, unsigned char *private_key32);
void calculate_dh1(unsigned char *scalar32, unsigned char *point32, unsigned char *out32);
void calculate_kdh1(unsigned char *in32, unsigned char *out32);
void calculate_h1(unsigned char *shared_key32, unsigned char *in, int len, unsigned char *challenge32, unsigned char *out32);
void calculate_challenge(unsigned char *out, int len);

void prepare_auth_authenticator(unsigned char *public_key132, unsigned char *public_key232, unsigned char *out64);
void prepare_auth_data(unsigned char type, unsigned int id, char *name, unsigned char *nonce32, unsigned char *out69);

void prepare_encrypted(unsigned char *key36, unsigned short cmd, unsigned char *payload, int len, unsigned char *nonce24, unsigned char *out);

unsigned short get_encrypted_msg_len(unsigned char *encrypted);

void decrypt_encrypted(unsigned char *shared_key32, unsigned char *encrypted, unsigned char *out);

unsigned char check_error(unsigned short expected, unsigned char *in, int in_len);

int decrypt_maybe(unsigned char *key36, unsigned char *in, int len, unsigned char *out256);

#endif