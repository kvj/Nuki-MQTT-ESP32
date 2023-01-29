#ifndef NUKI_HASS_H
#include "net.h"
#include <Preferences.h>
#include <set>

void hass_update_bridge(const char *address);
void hass_update_config(int type, const char *address, unsigned char *config);
void hass_update_authorizations(int type, const char *address, unsigned char *in);
void hass_remove_missing_authorizations(Preferences *preferences, const char *address, std::set<unsigned int> ids);
void hass_update_keypad_codes(int type, const char *address, unsigned char *in);
void hass_remove_missing_keypad_codes(Preferences *preferences, const char *address, std::set<unsigned int> ids);

#define NUKI_HASS_H
#endif