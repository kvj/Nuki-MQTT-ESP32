#ifndef UTUL_H
#define UTIL_H

#include <string>
#include <Arduino.h>

#define CAST_PUC (unsigned char *)

#ifndef NUKI_MQTT_VER
#define NUKI_MQTT_VER "dev"
#endif

void log_init(bool verbose);

void log_bytes(const char *module, const char *message, char *data, int len);
String convert_mac_id(const char *mac);

#endif