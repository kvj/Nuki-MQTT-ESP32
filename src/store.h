#ifndef NUKI_STORE_H

#include <Preferences.h>

#define PREF_PAIRING "pairing"
#define PREF_AUTH_IDS "auth_ids"
#define PREF_KEYPAD_IDS "keypad_ids"
#define PREF_PIN "pin"
#define PREF_PAIRING_LEN 38

void read_pairing_key(Preferences *preferences, unsigned char *out);
void store_pairing_key(Preferences *preferences, unsigned char *out);
void read_ids_array(Preferences *preferences, const char *name, unsigned char *out, int item_size = 2);
void store_ids_array(Preferences *preferences, const char *name, unsigned char *in, int item_size = 2);
unsigned short read_pin(Preferences *preferences);
void store_pin(Preferences *preferences, unsigned short pin);

#define NUKI_STORE_H
#endif