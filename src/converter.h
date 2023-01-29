#ifndef NUKI_CONVERT_H

#include <cstring>

void convert_state_to_json(unsigned char type, unsigned char *in, std::string *out);
unsigned char convert_action_from_json(unsigned char type, char *in);

std::string convert_config_to_json(unsigned char type, unsigned char *in);
int convert_config_from_json(unsigned char type, unsigned char *in, char *json, unsigned char *out);

std::string convert_info_to_json(unsigned char type, const char *address, bool paired, unsigned short pin);
void convert_error_to_json(unsigned char type, unsigned char code, std::string *out);
std::string convert_connection_status_to_json(unsigned char type, bool connected, int rssi);

void convert_pin_from_json(unsigned char type, char *in, unsigned short *out);

std::string convert_authorizations_to_json(unsigned char type, unsigned char *in);

std::string convert_keypad_codes_to_json(unsigned char type, unsigned char *in);
int convert_keypad_code_from_json(unsigned char type, unsigned char *in, char *json, unsigned char *out);

std::string convert_log_entry_to_json(unsigned char type, unsigned char *in);

unsigned int extract_id_from_data(unsigned char *in, int size);
unsigned int extract_id_from_json(const char *in);

#define NUKI_CONVERT_H
#endif