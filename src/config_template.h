#ifndef NUKI_CONFIG_H

#define CONFIG_VERBOSE_OUTPUT false

#define CONFIG_DEVICE_MAC "XX:XX:XX:XX:XX:XX"
#define CONFIG_REFRESH_STATE_MIN 60

#define CONFIG_WIFI_NAME "AP Name"
#define CONFIG_WIFI_PASSWORD "AP password"

#define CONFIG_MQTT_URI "mqtt://IP_ADDRESS:1883"
#define CONFIG_MQTT_CLIENT_ID "nuki_mqtt"
#define CONFIG_MQTT_PATH "nuki"

#define CONFIG_HOMEASSISTANT true
#define CONFIG_HASS_DISCOVERY_PREFIX "homeassistant"

#define NUKI_CONFIG_H
#endif