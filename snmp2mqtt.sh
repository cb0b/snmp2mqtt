#!/bin/bash
# Imports SNMP values to MQTT with configurable topics for MQTT
# currently only scalars are supported as MQTT values (one per OUI). The result gets embedded in a JSON string
# along with a timestamp. This is intended for an easy import via telegraf to influx.
# Configuration is done via confgile files to minimize effort with cron. Alternatively CLI parameters
# are intended for interactive use.
# e.g.
# ./snmp2mqtt.sh -c myconfFile4snmp2mqtt.conf ./testSNMPObj.conf,./secondTestObject.conf
# Both modes for MQTT are supported via conf file settings
# To make use of MQTT-TLS place the rootCA and subCA from the mqttserver certificate in a combined file and 
# configure it in ./snmp2mqtt.conf
# examples are provided in the config-file. This assumes of course the mqtt broker has already been configured
# for TLS.
# For mosquitto,org download the CA certificate from https://test.mosquitto.org/ssl/mosquitto.org.crt
# The username and password for MQTT can be empty for public (without auth) access to the broker. (This is intended
# to make it easier to do a quick test).
# Format of the mapping file:
# OID				 mqttTopic			  mapping for e.g. values to human-readable
# .1.3.6.1.4.1.14848.2.1.2.1.3.1 messpc/sensors/1/nSensorType     map:1=Test,2=test2
# Pick up the values and description from the vendor MIBs. The mibbrowser from ireasoning is working quite well
# There is a personal edition available at https://www.ireasoning.com/download.shtml
# To deal with MQTT I use the MQTT-Explorer which works really nice. (http://mqtt-explorer.com/)
#
# Not implemented yet:
# - use SNMPv3	holy crap - not easy with all the possibilities.
#
# Packages needed:
# apt install snmp mosquitto-clients
# home is at ~/projects/snmp2mqtt
# 
# run with cron for periodic updates
# With Debian11x64 use
# ---
# /etc/cron.d/snmp2mqtt
# m  h  dom mon dow user command
# */5 *  *   *   *   cb  /home/cb/snmp2mqtt >/dev/null
# ---
#
# A bit unrealated but quite annoying if the locale is not set/working as expected
# fix the locale problem on Debian:
# sudo vim /etc/default/locale
# LANGUAGE=en_US.UTF-8
# LANG=en_US.UTF-8
# or LANG=C
# LC_ALL=en_US.UTF-8
#
# sudo locale-gen en_US.UTF-8
# sudo dpkg-reconfigure locales
#
#
# (w) 2022 C::B0b
# $Id: snmp2mqtt.sh,v 2.8 2022/11/20 16:10:58$
# 
# History:
# 22.Nov 2022 v2 changed config format to be able to deal with multiple snmp targets in one go
# 15.Nov 2022 v1 first version
#
set -u
# set -e  # errorhandling
set -o pipefail

DEBUG=${DEBUG:=0}

SNMPHOST=test.mosquitto.org
SNMPCOMMUNITY=public
SNMPVERSION=1 
#configfile mapping OIDs to MQTT topics
SNMPMappingFile=./configTopics.conf

MQTTHOST=test.mosquitto.org
MQTT_USE_SSL="yes"
MQTTPORT=8883
MQTTCA=./mosquitto.org.crt
MQTTUSER=none
MQTTPASSWORD=justEmpty
MQTTCLIENTNAME=snmp2mqtt
MQTTTLSVERSION="tlsv1.2"	# see man mosquitto_pub
MQTTQOS=1			# see man mosquitto_pub
MQTTRETAIN=false		# see man mosquitto_pub

TMPCFG=/tmp/$$.snmp2mqtt.topicsmapping.txt


function dbg() {
    [ $DEBUG = "1" ] && echo "DEBUG:in function ${FUNCNAME[1]} -->  $*" >&2
}


function showVersion() {
    grep ',v' $0 |cut -f2 -d',' | cut -f1-4 -d' ' | head -1
    # egrep -A1 '^#.*History' sync2bak | tail -1 | cut -f2 -d'#' | cut -f2-4 -d' '
}


function usage() {
    local configFileName=$1
    echo "$0 [-d][-v][-c configFile.conf] [./snmp2mqttMapping.conf[,./snmp2mqttMapping2.conf]] | [-h|?]"
    echo "Version: $(showVersion)"
    echo "  -v be verbose. This in intended for interactive use"
    echo "  -d enable DEBUG mode"
    echo "  default for configFile is $configFileName"
    echo "  If the configfile does not exist an fresh conffile will be created for editing"
    echo "  Same applies for the mapping-file. If its missing a sample file gets created to get started"
    echo "Configure SNMP related things in the mapping file"
    echo "Configure MQTT related parameters in $configFileName along with the reference to the mapping files"
}


function cleanupMappingFile () {
    local snmp2mqttMappingFile=$1
    # an OID MUST start with a dot
    egrep -e'^\.[0-9]' $snmp2mqttMappingFile >$TMPCFG
}


function getSNMPHost () {
    local mappingFile=$1
    host=$(grep "SNMPHOST=" $mappingFile | cut -f2 -d'=')
    dbg "host=$host"
    [ -n $host ] && echo $host || echo "$SNMPHOST"
}


function getSNMPcommunity() {
    local mappingFile=$1
    community=$(grep "SNMPCOMMUNITY=" $mappingFile | cut -f2 -d'=')
    [ -n $community ] && echo $community || echo "$SNMPCOMMUNITY"
}


function getSNMPversion() {
    local mappingFile=$1
    ver=$(grep "SNMPVERSION=" $mappingFile | cut -f2 -d'=')
    [ -n $ver ] && echo $ver || echo "$SNMPVERSION"
}


function parseOID() {
    local line=$*
    dbg "parsing OID from line: $line"
    # .1.3.6.1.4.1.14848.2.1.1.3.0   messpc/sensors/nSensorTempUnit map:0=Celsius,1=Fahrenheit,2=Kelvin
    # .1.3.6.1.4.1.14848.2.1.1.1.0   messpc/sensors/version map:
    echo ${line%% *}
}


function parseTOPIC() {
    local line=$*
    topicRaw=${line##* }
    # DEBUG: topicRaw=messpc/sensors/1/nSensorType    map:1=Test,2=test2
    topic=$(echo "$line" | awk '{print $2}')
    dbg "topic=$topic"
    echo $topic
}


function isHexString() {
    local oid=$1
    local equal=$2
    local type=$3
    dbg "type=$type"	# Hex-String:
    # DEBUG: iso.3.6.1.4.1.14848.2.1.2.1.6.8 = Hex-STRING: 20 32 33 2E 34 20 B0 43
    [ "$type" == "Hex-STRING:" ] && echo "yes" || echo "no"
}


function isTimeticks () {
    local oid=$1
    local equal=$2
    local type=$3
    # iso.3.6.1.4.1.318.1.1.1.2.2.3.0 = Timeticks: (1308000) 3:38:00.00
    [ "$type" == "Timeticks:" ] && echo "yes" || echo "no"
}


function convertHexString2Ascii () {
    hexValues="$*"
    str=""
    for v in $hexValues
    do
        # echo "v=$v"
        v="\x${v}"
        str=$(printf "${str}$v")
        # echo "str=$str"
    done
    echo "$str"
}


function extractDatatype () {
    # DEBUG: iso.3.6.1.4.1.14848.2.1.2.1.6.8 = Hex-STRING: 20 32 33 2E 34 20 B0 43
    iso=$1
    equal=$2
    dataType=$3
    dbg "parameters $*"
    # Hex-STRING: INTEGER: IpAddress: MIB STRING: Timeticks:
    # Counter64: Counter32: Gauge32: Hex-STRING: INTEGER: IpAddress: No OID: STRING: Timeticks:
    echo ${dataType%:*}
}


function getSNMP() {
    local oid=$1
    local dataType=""
    dbg "SNMPVersion=$SNMPVERSION Community=$SNMPCOMMUNITY Host=$SNMPHOST"
    sensorValueRaw=$(snmpget -v$SNMPVERSION -c $SNMPCOMMUNITY $SNMPHOST $oid )
    if [ $? -ne 0 ]
    then
        echo "ERROR"
    else
        dbg "$sensorValueRaw" # iso.3.6.1.4.1.14848.2.1.2.1.2.1 = STRING: "Kombi Sensor 30119"
        # DEBUG: iso.3.6.1.4.1.14848.2.1.2.1.6.8 = Hex-STRING: 20 32 33 2E 34 20 B0 43
        # do some mapping if requested and conversion from hexbyte to string where applicable
        dbg "extactDatatype with $sensorValueRaw"
        IFS=' ' dataType=$(extractDatatype $sensorValueRaw)
        dbg "Datatype $dataType"
        IFS=' '
        if [ $(isHexString $sensorValueRaw) == 'yes' ]
        then
            # make the crap readable
            echo "STRING" "$(convertHexString2Ascii ${sensorValueRaw#*: })"
        else
            if [ $dataType == "STRING" ]
            then
                # remove the quotes as they get added later again
                value=$(echo ${sensorValueRaw#*:} | sed 's/"//g')
                dbg "value cleanedup: $value"
                echo "$dataType" "$value" 
            else
                if [ $(isTimeticks $sensorValueRaw) == 'yes' ]
                then
                    # iso.3.6.1.4.1.318.1.1.1.2.2.3.0 = Timeticks: (1308000) 3:38:00.00
                    # cleanup so that influx can deal with the value
                    dbg "found timeticks"
                    value=${sensorValueRaw#*: }
                    dbg "value=$value"
                    value=$(echo ${sensorValueRaw#*: } | cut -f1 -d')' | sed -e 's/(//' )
                    dbg "parse it: $sensorValueRaw --> $value"
                else
                    value="${sensorValueRaw#*:}"
                fi
                dbg "returning datatype: $dataType  value: $value"
                echo "$dataType" "$value"
            fi
        fi
    fi
}


function parseMapping() {
    local line=$*
    # .1.3.6.1.4.1.14848.2.1.2.1.3.1 messpc/sensors/1/nSensorType     map:1=Test_1,2=test2
    mapping=$(echo "$line" | awk '{print $3}' | cut -f2 -d':')
    dbg "mapping=$mapping"
    echo "$mapping"
}


function mapSNMPvalue() {
    local mapping=$1            # 1=Test_for_case_one,2=test2
    local valueRaw=$2
    local value=""
    local m
    local v
    dbg "mapping=$mapping"
    dbg "valueRaw=$valueRaw"
    IFS=,
    #for map in ${mapping//,/ }
    for map in $mapping
    do
        dbg "loop: mapping def=$map"
        m=${map%%=*}
        dbg "m=$m"
        if [ "$valueRaw" == "${m}" ]
        then
            v=${map##*=}
            dbg "v=$v"
            value=${v}
            dbg "match found replace int with string: $m --> $v"
            echo "$value($m)"
            return
        fi
    done
    echo "$value"
}


function createConfigFile () {
    local snmp2mqttMappingFileName=$1
    echo "# configfile for $0 created $(date) on $(hostname) /C::B0b" >$snmp2mqttMappingFileName
    echo "MQTTHOST=$MQTTHOST">>$snmp2mqttMappingFileName
    echo "MQTT_USE_SSL=$MQTT_USE_SSL # or no">>$snmp2mqttMappingFileName
    echo "MQTTCA=$MQTTCA">>$snmp2mqttMappingFileName
    echo "MQTTPORT=$MQTTPORT # 1883 for unencryoted and 8883 for SSL">>$snmp2mqttMappingFileName
    echo "MQTTUSER=$MQTTUSER # can be none">>$snmp2mqttMappingFileName
    echo "MQTTPASSWORD=$MQTTPASSWORD">>$snmp2mqttMappingFileName
    echo "MQTTTLSVERSION=$MQTTTLSVERSION">>$snmp2mqttMappingFileName
    echo "MQTTQOS=$MQTTQOS">>$snmp2mqttMappingFileName
    echo "MQTTRETAIN=$MQTTRETAIN">>$snmp2mqttMappingFileName
    echo "MQTTCLIENTNAME=$MQTTCLIENTNAME">>$snmp2mqttMappingFileName
    echo "# please edit SNMPMappingFile=$SNMPMappingFile">>$snmp2mqttMappingFileName
} 


function createOIDmappingFile() {
    local snmp2mqttMappingFileName=$1
    echo "# configfile for $0 created $(date) on $(hostname) /C::B0b" >$snmp2mqttMappingFileName
    echo "# This is an example how to build the input defintion mapping snmpOIDs to mqtt topics" >>$snmp2mqttMappingFileName
    echo "SNMPHOST=$SNMPHOST" >>$snmp2mqttMappingFileName
    echo "SNMPCOMMUNITY=$SNMPCOMMUNITY" >>$snmp2mqttMappingFileName
    echo "SNMPVERSION=$SNMPVERSION" >>$snmp2mqttMappingFileName
    echo "# ---" >>$snmp2mqttMappingFileName
    echo "# NB: mapping must NOT contain blanks or other whitepaces" >>$snmp2mqttMappingFileName
    echo "# OIDs MUST start with a dot in col 1" >>$snmp2mqttMappingFileName
    echo ".1.3.6.1.4.1.14848.2.1.1.3.0   messpc/sensors/nSensorTempUnit   map:0=Celsius,1=Fahrenheit,2=Kelvin" >>$snmp2mqttMappingFileName
    echo ".1.3.6.1.4.1.14848.2.1.1.1.0   messpc/sensors/version           map:" >>$snmp2mqttMappingFileName
    echo "# ---" >>$snmp2mqttMappingFileName
    echo "# eof" >>$snmp2mqttMappingFileName
}


function readMappingFileList () {
    local confFile="$1"
    dbg "confFile=$confFile to read SNMPMappingFile="
    mappingFileList=$(grep ^SNMPMappingFile "$confFile" | cut -f2 -d'=')
    dbg "found $mappingFileList in $confFile"
    echo "$mappingFileList"
}


function convert2json() {
    local v=$1
    local dataType=$2
    dateISO8601=$(date --iso-8601=seconds)
    # Hex-STRING: INTEGER: IpAddress: MIB STRING: Timeticks:
    # Counter32: Gauge32: Hex-STRING: INTEGER: IpAddress: No OID: STRING: Timeticks:
    case $dataType in 
        INTEGER|Integer|integer|Timeticks|Counter32|Gauge32)
            # use literal
            # only numbers will not be quoted in json
            echo '{"Time":"'$dateISO8601'","Datatype":"'$dataType'","value":'$v'}'
	    ;;
        *)
            # enquote
            echo '{"Time":"'$dateISO8601'","Datatype":"'$dataType'","value":"'$v'"}'
	    ;;
    esac
}


function formatRetainFlag() {
   local retainReq=$1
   if [ $retainReq == "true" ]
   then
       echo "-r"
   else
       echo " "
   fi
}

function verb () {
    [ $verbose = "1" ] && echo "$*"
}


# --------------------------------------------------------------------------------------
# main starts here

# check for a conf file in pwd
# %%.* removes all after the dot
snmp2mqttConfFile="${0%%.sh}.conf"
verbose=0
while getopts ":c:dvh?" options; do
  case $options in
    c ) snmp2mqttConfFile="$OPTARG";;
    v ) verbose=1;;
    d ) DEBUG=1;;
    h ) usage $snmp2mqttConfFile; exit 3;;
    \? ) usage $snmp2mqttConfFile; exit 3;;
    * ) usage $snmp2mqttConfFile; exit 3;;
  esac
done
shift $(($OPTIND -1))
verb "$0 $(showVersion)"

if [ -f "$snmp2mqttConfFile" ]
then
    dbg "source configfile $snmp2mqttConfFile"
    source "$snmp2mqttConfFile"
    dbg "set all configured values from $snmp2mqttConfFile"
    verb "using conffile $snmp2mqttConfFile"
else
    echo "conffile $snmp2mqttConfFile not found - create it with default values"
    createConfigFile "$snmp2mqttConfFile"
    echo "created $snmp2mqttConfFile - please configure the settings there"
    exit 3
fi
dbg "sanity checks for MQTT via SSL"
# verify prereq for MQTT via SSL
if [ "$MQTT_USE_SSL" == "yes" ]
then
    dbg "MQTT_USE_SSL = YES - next check for CA File"
    if [ ! -f "$MQTTCA" ]
    then
        echo "ERROR: CA File $MQTTCA for MQTT-SSL not found or not readable - exit" >&2
        exit 3
    else
        verb "SSL configured: found CA $MQTTCA"
    fi
else
    verb "MQTT cleartext configured - consider to use TLS"
fi

# loop over all SNMPMappingFiles defined in the confFile or provieded by CLI
dbg "check if a mapping-file has been provided by CLI"
dbg "number of CLI parameters: $#"
if [ $# -eq 1 ]
then
    dbg "mapping file provided: $1 via CLI"
    snmpMappingFileList="$1"
else
    # SNMPMappingFile=./configTopicsUPSrm700.conf,./configTopicsUSPrm750.conf
    dbg "get snmpMapping2MQTT definiton from $snmp2mqttConfFile"
    # check that the keyword is setup
    grep -q "^SNMPMappingFile" $snmp2mqttConfFile
    if [ $? -ne 0 ]
    then
        echo "ERROR: please define keyword \"SNMPMappingFile=\" in $snmp2mqttConfFile" >&2
        exit 3
    fi
    snmpMappingFileList=$(readMappingFileList $snmp2mqttConfFile)
fi
dbg "snmpMappingFileList=$snmpMappingFileList"

IFS=,
for snmp2mqttMappingFile in $snmpMappingFileList
do
    dbg "-----> working on $snmp2mqttMappingFile"
    if [ ! -r $snmp2mqttMappingFile ]
    then
       echo "WARN: Configfile $snmp2mqttMappingFile does not exist or is not readable - skip it" >&2
       # take the next in the list and create a sample file
       echo "INFO: a sample OIDmappingFile named $snmp2mqttMappingFile has been created for further configuration"
       createOIDmappingFile "$snmp2mqttMappingFile"
       sleep 10
       continue
    fi
    verb "working with mappingfile $snmp2mqttMappingFile"
    # read settings from currently active conf-file
    SNMPHOST=$(getSNMPHost $snmp2mqttMappingFile)
    dbg "using SNMPHOST=$SNMPHOST"
    SNMPCOMMUNITY=$(getSNMPcommunity $snmp2mqttMappingFile)
    dbg "using SNMPCOMMUNITY=$SNMPCOMMUNITY"
    SNMPVERSION=$(getSNMPversion $snmp2mqttMappingFile)
    dbg "using SNMPVERSION=$SNMPVERSION"

    cleanupMappingFile $snmp2mqttMappingFile	# this creates the TMPFILE for input
    while read line
    do
        oid=$(parseOID "$line")
        mqttTopic=$(parseTOPIC "$line")
        mapping=$(parseMapping "$line")
        if [ -n "$oid" ] && [ -n "$mqttTopic" ]
        then
            #get SNMP value and datatype 
            IFS=' '
            read dataType value < <(getSNMP $oid)
            dbg "getSNMP value=$value dataType=$dataType"
            if [ "$value" == "ERROR" ]
            then
                echo "WARN: SNMP OID $oid is invalid - ignored"
		continue
            fi
            dbg "value from getSNMP for $oid = $value"
            if [ -n "$value" ] 
            then
                if [ -n "$mapping" ]
                then
                    dbg "call mapSNMPvalue $mapping $value" 
                    value=$(mapSNMPvalue "$mapping" "$value")
                    dbg "value(new)=$value"
                    dataType="STRING"
                fi
                value=$(convert2json "$value" "$dataType")
                dbg "publish Topic -> $mqttTopic  value -> $value"
                RETAIN=$(formatRetainFlag $MQTTRETAIN)
                if [ "$MQTT_USE_SSL" == "yes" ]
                then
                    dbg "using mqtt via SSL: Server=$MQTTHOST CAFile=$MQTTCA port=$MQTTPORT"
                    if [ "$MQTTUSER" != "none" ]
                    then
                        dbg "Using MQTTUSER=$MQTTUSER for authentication via SSL"
                        mosquitto_pub -i $MQTTCLIENTNAME -q $MQTTQOS $RETAIN --cafile "$MQTTCA" --tls-version $MQTTTLSVERSION -u "$MQTTUSER" -P "$MQTTPASSWORD" -h "$MQTTHOST" -p "$MQTTPORT" -t "$mqttTopic" -m "$value"
                    else
                        dbg "unauthenticated but SSL unecrypted access to MQTT server consider configuring MQTTUSER & MQTTPASSWORD"
                        mosquitto_pub -i $MQTTCLIENTNAME -q $MQTTQOS $RETAIN --cafile "$MQTTCA" --tls-version $MQTTTLSVERSION -h "$MQTTHOST" -p "$MQTTPORT" -t "$mqttTopic" -m "$value"
                    fi
                    verb "published $mqttTopic: $value"
                else
                    dbg "using mqtt clear-text: Server=$MQTTHOST port=$MQTTPORT"
                    if [ "$MQTTUSER" != "none" ]
                    then
                        dbg "Using MQTTUSER=$MQTTUSER for authentication via SSL"
                        mosquitto_pub -i $MQTTCLIENTNAME -q $MQTTQOS $RETAIN -u "$MQTTUSER" -P "$MQTTPASSWORD" -h "$MQTTHOST" -p "$MQTTPORT" -t "$mqttTopic" -m "$value"
                    else
                        dbg "unauthenticated and unecrypted access to MQTT server consider configuring MQTTUSER & MQTTPASSWORD"
                        mosquitto_pub -i $MQTTCLIENTNAME -q $MQTTQOS $RETAIN -h "$MQTTHOST" -p "$MQTTPORT" -t "$mqttTopic" -m "$value"
                    fi
                    verb "published $mqttTopic: $value"
                fi
            fi
        fi
    done <$TMPCFG
    [ $DEBUG = 0 ] && rm $TMPCFG
done
