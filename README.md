# snmp2mqtt
Reads OIDs from SNMP and sends them to MQTT

## snmp2mqtt.sh Imports SNMP values to MQTT with configurable topics for MQTT and is written in bash

Currently only scalars are supported as MQTT values (one per OUI). The result gets embedded in a JSON string
along with a timestamp. This is intended for an easy import via telegraf to influx.
The configuration is done via confgile two files. Alternatively CLI parameters are possible and
intended for interactive use.  e.g.

 ./snmp2mqtt.sh -c myconfFile4snmp2mqtt.conf ./testSNMPObj.cfg,./secondTestObject.cfg

Both encrypted and unencrypted modes for MQTT are supported via conf file settings. Default is ./snmp2mqtt.conf

To make use of MQTT-TLS place the rootCA and if needed all subCA(s) from the mqttserver certificate in a combined 
file and configure it in ./snmp2mqtt.conf
If the config file does not exist an new one will be created with default values. Please adjust to your needs.

For mosquitto.org download the CA certificate from https://test.mosquitto.org/ssl/mosquitto.org.crt
The username and password for MQTT can be empty for public (without auth) access to the broker. This is intended
to make it easier to do a quick test.

## Format of the mapping file:
The mapping file contains the OIDs of the device under examination. Typically vendors provide MIBs with the 
corresponding description of each OID. This is the source for the mapping file.
The format is:

```
 OID				mqttTopic			 mapping for e.g. values to human-readable
 .1.3.6.1.4.1.14848.2.1.2.1.3.1 messpc/sensors/1/nSensorType     map:1=Test,2=test2
```

The mibbrowser from ireasoning is working quite well. There is a personal edition available at 
https://www.ireasoning.com/download.shtml
To deal with MQTT I use the MQTT-Explorer which works really nice. (http://mqtt-explorer.com/)

Not implemented yet:
 - use SNMPv3

## Packages needed on Debian:
```
 apt install snmp mosquitto-clients
```
 

## periodic execution

Run it with cron for periodic updates 

on Debian10/Debian11 use


 /etc/cron.d/snmp2mqtt
```
 m  h  dom mon dow user command
 */5 *  *   *   *   cb  /home/cb/snmp2mqtt >/dev/null
```

This will run snmp2mqtt every 5 minutes doing the update.

