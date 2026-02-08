#!/bin/bash

CM_MAC=$(deviceinfo.sh -cmac | tr -d ':' | tr '[:lower:]' '[:upper:]')
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="/tmp/WFO_${CM_MAC}_${TIMESTAMP}.log"
CONFIG_FILE="/var/tmp/Gateway_Config.json"
#LOG_FILE="/var/tmp/monitor.log"
PING_STATE_FILE="/tmp/ping_state"
MODE_STATE_FILE="/tmp/mode_state"

SCRIPT_NAME=$(basename "$0")

########################################
# Logging Function
########################################
log_msg() {
    echo "$(date '+%F %T') - $1" >> "$LOG_FILE"
    sync
}

########################################
# Cleanup old logs
########################################
PREFIX1="WFO_${CM_MAC}"
PREFIX2="GFO_${CM_MAC}"

find /var/tmp -maxdepth 1 -type f \
    \( -name "${PREFIX1}*" -o -name "${PREFIX2}*" \) \
    | while IFS= read -r f; do
        log_msg "Removing old log: $f"
        rm -f "$f"
    done

########################################
#
########################################


get_model_info() {
    # Usage: get_model_info "PRODUCT_CODE"
    local code="$1"

    case "$code" in
        WNXL11BWL) echo "XLE" ;;
        WNXL11BWX) echo "XLE" ;;
        XXXXXXXXX) echo "Vantiva XB9" ;;
        SCER11BEL) echo "Serrcom XER10" ;;
        YYYYYYYYY) echo "Serrcom XB10" ;;
        SCXF11BFL) echo "XF10" ;;
        CGM601TCOM)   echo "Vantiva XB10" ;;
        CVA601ZCOM)   echo "XD4" ;;
        CGM4981COM) echo "TCH XB8" ;;
        CGA4332COM) echo "TCH CBR2" ;;
        CGA4131COM) echo "TCH CBR" ;;
        CGM4331COM) echo "TCH XB7" ;;
        TG4482A)   echo "Comm XB7" ;;
        TG3482G)   echo "Arris XB6" ;;
        DPC3941T)  echo "Cisco XB3 3941T" ;;
        TG1682G)   echo "Arris XB3" ;;
        DPC3941B)  echo "Cisco XB3 3941B" ;;
        DPC3939T)  echo "Cisco XB3 3939" ;;
        DPC3939B)  echo "Cisco XB3 3939 BWG" ;;
        *) echo "Unknown product code: $code" ;;
    esac
}

########################################
# READ WAN IP
########################################
WAN_IP=$(awk -F'"' '/current_wan_ipaddr/ {print $4}' "$CONFIG_FILE")
[[ -z "$WAN_IP" ]] && { log_msg "WAN IP missing"; exit 1; }

########################################
# INITIAL STATES
########################################
echo "UP" > "$PING_STATE_FILE"
echo "UNKNOWN" > "$MODE_STATE_FILE"

########################################
# SAFE DMCLI
########################################
safe_dmcli() {
    dmcli eRT getv "$1" 2>/dev/null | awk -F'value:' '/value:/ {print $2}' | sed 's/^ *//' | xargs
}

########################################
# Function to fetch all gateway statuses
########################################

get_gateway_status() {
    local G1A G1O G2A G2O
    G1A=$(safe_dmcli "Device.X_RDK_GatewayManagement.Gateway.1.ActiveStatus")
    G1O=$(safe_dmcli "Device.X_RDK_GatewayManagement.Gateway.1.OperationStatus")
    G2A=$(safe_dmcli "Device.X_RDK_GatewayManagement.Gateway.2.ActiveStatus")
    G2O=$(safe_dmcli "Device.X_RDK_GatewayManagement.Gateway.2.OperationStatus")

    # Return as space-separated values
    echo "$G1A $G1O $G2A $G2O"
}

########################################
#
########################################

check_heartbeat() {
    REM_STATUS=$(safe_dmcli "Device.X_RDK_Remote.Device.2.Status")
    GW_MODEL=$(safe_dmcli "Device.X_RDK_Remote.Device.2.ModelNumber")

    EXPECTED_REMOTE="3"
    [ "$GW_MODEL" = "SCXF11BFL" ] || [ "$GW_MODEL" = "SCER11BE" ] && EXPECTED_REMOTE="2"

    [ "$REM_STATUS" = "$EXPECTED_REMOTE" ] && echo "Available" || echo "NOT Available"
}


# Read Current Firmwar Name
log_msg "XLE Firmware: $(deviceinfo.sh -fw)"

########################################
# Read Inputs Before/After Validation
########################################

verify_restore_conditions() {
    CONTEXT="$1"   # PRE or RESTORE
    stats="$(date)"

    DEBUG_STEP="Function call check"
    if [[ "$CONTEXT" != "PRE-GFO" && "$CONTEXT" != "RESTORE" ]]; then
        echo "Failed at: $DEBUG_STEP"
        return 1
    fi

    DEBUG_STEP="Detect interface g-*"
    REAL_IFACE=$(ovs-vsctl list-ifaces br-home | grep '^g-' | sed 's/^g-//')
    [[ -z "$REAL_IFACE" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="Check IP on REAL_IFACE"
    IP_ADDR=$(ifconfig "$REAL_IFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d: -f2)
    [[ -z "$IP_ADDR" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="Check IP on brWAN"
    BRWAN_IP=$(ifconfig brWAN 2>/dev/null | awk '/inet / {print $2}' | cut -d: -f2)
    [[ -z "$BRWAN_IP" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="Check IP on br-home"
    BRHOME_IP=$(ifconfig br-home 2>/dev/null | awk '/inet / {print $2}' | cut -d: -f2)
    [[ -z "$BRHOME_IP" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="Detect backhaul type"
    #BH_IFACE=$(ovs-vsctl list-ifaces br-home | grep -E '^(g-wl0|g-wl1|g-wl2|eth0\.123|eth1\.123)$')
    #[[ -z "$BH_IFACE" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    # Determine type
    if echo "$REAL_IFACE" | grep -qE 'wl0|wl1|wl2'; then
        BACKHAUL_TYPE="Wi-Fi"
    elif echo "$REAL_IFACE" | grep -qE 'eth0\.123|eth1\.123'; then
        BACKHAUL_TYPE="Eth"
    else
        echo "Failed at: $DEBUG_STEP"
        return 1
    fi

    DEBUG_STEP="Check IP on wwan0"
    WWAN0_IP=$(ifconfig wwan0 2>/dev/null | awk '/inet / {print $2}' | cut -d: -f2)
    [[ -z "$WWAN0_IP" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="Check IP6 on wwan0"
    WWAN0_IP6=$(ifconfig wwan0 | awk '/Scope:Global/{print $3}')
    [[ -z "$WWAN0_IP6" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    WAN_IF=$(sysevent get current_wan_ifname)
    DEBUG_STEP="Check WAN Interface based on CONTEXT"
    if [[ "$CONTEXT" == "PRE-GFO" ]]; then
        EXPECTED_IF="br-home"
    elif [[ "$CONTEXT" == "RESTORE" ]]; then
        EXPECTED_IF="br-home"
    elif [[ "$CONTEXT" == "GFO" ]]; then
        EXPECTED_IF="wwan0"
    else
        echo "Unknown CONTEXT: $CONTEXT"
        #exit 1
    fi

    # Validate current interface
    if [[ "$WAN_IF" != "$EXPECTED_IF" ]]; then
        echo "Fail at: $DEBUG_STEP (Expected: $EXPECTED_IF, Got: $WAN_IF)"
        exit 1
    fi

    # Check DNS resolution for IPv4 and IPv6
    DNS4="Fail"
    DNS6="Fail"

    NS=$(nslookup google.com 2>/dev/null)
    echo "$NS" | grep -qE "([0-9]{1,3}\.){3}[0-9]{1,3}" && DNS4="Pass"
    echo "$NS" | grep -qE "([0-9a-fA-F]{0,4}:){2,}" && DNS6="Pass"

    DEBUG_STEP="Check mesh_wan_linkstatus"
    LINK_STATUS=$(sysevent get mesh_wan_linkstatus)
    [[ "$LINK_STATUS" != "up" ]] && { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="Fetch common values"
    NETWORK_MODE=$(deviceinfo.sh -mode)
    NET_MODE=$(safe_dmcli "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode")
    FAILOVER_EN=$(safe_dmcli "Device.X_RDK_GatewayManagement.Failover.Enable")
    XLE_CAPABILITY=$(safe_dmcli "Device.X_RDK_Remote.Device.1.Capabilities")
    GW_CAPABILITY=$(safe_dmcli "Device.X_RDK_Remote.Device.2.Capabilities")
    GW_MAC=$(safe_dmcli "Device.X_RDK_Remote.Device.2.MAC")
    GW_MODEL=$(safe_dmcli "Device.X_RDK_Remote.Device.2.ModelNumber")
    GW_PRODUCT=$(get_model_info "$GW_MODEL")

    DEBUG_STEP="Fetch Gateway Management parameters"
    read G1A G1O G2A G2O <<< "$(get_gateway_status)"

    DEBUG_STEP="Networking mode validation"
    [[ "$NET_MODE" == "1" || "$NETWORK_MODE" == "Extender" ]] || { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="Failover.Enable validation"
    [[ "$FAILOVER_EN" == "1" ]] || { echo "Failed at: $DEBUG_STEP"; return 1; }
    
    DEBUG_STEP="Heartbeat validation"
    REM_STATUS=$(safe_dmcli "Device.X_RDK_Remote.Device.2.Status")
    HB_STATE=$([[ "$REM_STATUS" == "3" ]] && echo "Available" || echo "NOT Available")
    [[ "$REM_STATUS" == "3" ]] || { echo "Failed at: $DEBUG_STEP"; return 1; 

    DEBUG_STEP="XLE Capabilities check"
    [[ -n "$XLE_CAPABILITY" ]] || { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="XB Capabilities check"
    [[ -n "$GW_CAPABILITY" ]] || { echo "Failed at: $DEBUG_STEP"; return 1; }

    DEBUG_STEP="GatewayManagement 4 params validation"
    [[ "$G1A" == "true" ]] || { echo "Failed at: $DEBUG_STEP G1A"; return 1; }
    [[ "$G1O" == "true" ]] || { echo "Failed at: $DEBUG_STEP G1O"; return 1; }
    [[ "$G2A" == "false" ]] || { echo "Failed at: $DEBUG_STEP G2A"; return 1; }
    [[ "$G2O" == "true" ]] || { echo "Failed at: $DEBUG_STEP G2O"; return 1; }

    Account_Info=$(safe_dmcli "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AccountInfo.AccountID")
    WAN_EN=$(safe_dmcli "Device.X_RDK_WanManager.AllowRemoteInterfaces")

    if [[ "$CONTEXT" == "PRE-GFO" ]]; then
        log_msg "XLE Stats Time: $stats"
        log_msg "Account Info=$Account_Info"
        log_msg "GW_PRODUCT=$GW_PRODUCT | GW_MODEL=$GW_MODEL | GW_MAC=$GW_MAC"
        log_msg "Cellular Interface IP=$WWAN0_IP | $WWAN0_IP6"
        log_msg "$BACKHAUL_TYPE Backhaul | $REAL_IFACE Interface | $REAL_IFACE IP $IP_ADDR"
        log_msg "brWAN IP=$BRWAN_IP | br-home IP=$BRHOME_IP"
        log_msg "Mesh Link Status=$LINK_STATUS"
        log_msg "Networking Mode=$NETWORK_MODE | Gateway Failover=$FAILOVER_EN | WAN Failover=$WAN_EN"
        log_msg "Heart Beat Status=$HB_STATE"
        log_msg "XLE Capabilities=$XLE_CAPABILITY"
        log_msg "Gateway Capabilities=$GW_CAPABILITY"
        log_msg "GW1_Active=$G1A, GW1_Operation=$G1O, GW2_Active=$G2A, GW2_Operation=$G2O"
        log_msg "CONTEXT=$CONTEXT | Interface=$WAN_IF | DNS4=$DNS4 | DNS6=$DNS6"
        log_msg ">>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<"
    fi

    return 0 # Success message
}

########################################
# Pre Gateway Failover Check
########################################

verify_restore_conditions PRE-GFO
RESULT=$?
if [[ $RESULT -eq 0 ]]; then
    log_msg "XB-XLE setup looks good before GFO"
else
    log_msg "XB-XLE setup don't look good before GFO, Aborting the validation"
    #exit 1
fi

########################################
# THREAD 1 – SILENT PING MONITOR
########################################
(
    while true; do
        if ping -I wwan0 -c 1 -W 2 "$WAN_IP" >/dev/null; then
            echo "UP" > "$PING_STATE_FILE"
        else
            echo "DOWN" > "$PING_STATE_FILE"
        fi
        sleep 2
    done
) &

########################################
# THREAD 2 – SILENT MODE MONITOR
########################################
(
    while true; do
        MODE=$(deviceinfo.sh -mode 2>/dev/null)
        if [[ "$MODE" == "Extender" ]]; then
            echo "EXTENDER" > "$MODE_STATE_FILE"
        elif [[ "$MODE" == "Gateway" ]]; then
            echo "ROUTER" > "$MODE_STATE_FILE"
        else
            echo "UNKNOWN" > "$MODE_STATE_FILE"
        fi
        sleep 5
    done
) &

########################################
# THREAD 3 – STA BACKHAUL PING MONITOR
########################################

STA_PING_STATE_FILE="/tmp/sta_ping_state"
echo "UP" > "$STA_PING_STATE_FILE"

(
    while true; do

        WAN_IF=$(sysevent get current_wan_ifname)

        ###############################################################
        # 1. If WAN is wwan0 → always mark STA as DOWN
        ###############################################################
        if [[ "$WAN_IF" == "wwan0" ]]; then
            echo "DOWN" > "$STA_PING_STATE_FILE"
            sleep 2
            continue
        fi

        ###############################################################
        # 2. If WAN is br-home → perform STA Backhaul Ping test
        ###############################################################
        if [[ "$WAN_IF" == "br-home" ]]; then

            # Detect STA interface (g-wl0 / g-wl1 / g-wl2 / g-eth0.123 / g-eth1.123)
            STA_IFACE=$(ovs-vsctl list-ifaces br-home | grep '^g-' | sed 's/^g-//')

            if [[ -n "$STA_IFACE" ]]; then
                # Read STA IP (example: 169.254.1.180)
                STA_IP=$(ifconfig "$STA_IFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d: -f2)

                if [[ -n "$STA_IP" ]]; then
                    # Convert 169.254.X.Y → 169.254.X.1
                    STA_GW_IP=$(echo "$STA_IP" | awk -F. '{print $1"."$2"."$3".1"}')

                    # STA Gateway Ping Test
                    if ping -c 2 -W 2 "$STA_GW_IP" >/dev/null; then
                        echo "UP" > "$STA_PING_STATE_FILE"
                    else
                        echo "DOWN" > "$STA_PING_STATE_FILE"
                    fi
                else
                    echo "DOWN" > "$STA_PING_STATE_FILE"
                fi
            else
                echo "DOWN" > "$STA_PING_STATE_FILE"
            fi
        else
            ###########################################################
            # Any unknown WAN_IF (very rare) -> mark STA as DOWN
            ###########################################################
            echo "DOWN" > "$STA_PING_STATE_FILE"
        fi

        sleep 2
    done
) &

########################################
# MAIN LOOP (Rewritten Logic)
########################################

FAILOVER_DONE="false"
RESTORE_DONE="false"

# Timers
STA_DROP_TIME=0
MODE_ROUTER_TIME=0
GFO_TIME=0
RESTORE_START=0
MODE_EXTENDER_TIME=0
STA_RESTORE_TIME=0
RESTORE_END=0

LAST_STA_STATE="UP"

while true; do
    CUR_STA_PING=$(cat "$STA_PING_STATE_FILE" 2>/dev/null)
    CUR_MODE=$(cat "$MODE_STATE_FILE" 2>/dev/null)
    CUR_GW_PING=$(cat "$PING_STATE_FILE" 2>/dev/null)

    ########################################
    # 1. Detect STA Backhaul Drop
    ########################################
    if [[ "$LAST_STA_STATE" == "UP" && "$CUR_STA_PING" == "DOWN" && "$FAILOVER_DONE" == "false" ]]; then
        STA_DROP_TIME=$(date +%s)
        log_msg "STA Backhaul LOST → Triggering GFO Monitoring"
    fi
    LAST_STA_STATE="$CUR_STA_PING"

    ########################################
    # 2. Detect Mode Switch → ROUTER
    ########################################
    if [[ $MODE_ROUTER_TIME -eq 0 && "$CUR_MODE" == "ROUTER" ]]; then
        MODE_ROUTER_TIME=$(date +%s)
        log_msg "Mode switched: EXTENDER → ROUTER"

        if [[ $STA_DROP_TIME -gt 0 ]]; then
            DELTA=$(( MODE_ROUTER_TIME - STA_DROP_TIME ))
            log_msg "Time (STA Drop → Mode Router) = ${DELTA}s"
        fi
    fi

    ########################################
    # 3. Detect Gateway Failover Success
    ########################################
    if [[ "$FAILOVER_DONE" == "false" && "$CUR_MODE" == "ROUTER" ]]; then

        read G1A G1O G2A G2O <<< "$(get_gateway_status)"

        if [[ "$G2A" == "true" && "$G2O" == "true" &&
              "$G1A" == "false" && "$G1O" == "false" ]]; then

            GFO_TIME=$(date +%s)
            FAILOVER_DONE="true"
            log_msg "Gateway Failover SUCCESS."
            RESTORE_START=$(date +%s)
            if [[ $MODE_ROUTER_TIME -gt 0 ]]; then
                DELTA=$(( GFO_TIME - MODE_ROUTER_TIME ))
                log_msg "Time (Mode Router → Failover Success) = ${DELTA}s"
            fi

            #RESTORE_START=$(date +%s)
            sleep 30
            # Read Data from XLE after GFO
            log_msg "BRLAN0 IPv4: $(ifconfig brlan0 | awk '/inet addr/{print $2}' | cut -d: -f2)"
            log_msg "BRLAN0 IPv6: $(ifconfig brlan0 | awk '/Scope:Global/{print $3}')"
            zebra_value=$(awk '/^interface /{iface=$2} /ipv6 nd prefix fd01/{print iface": "$4}' /var/zebra.conf)
            log_msg "Zebra Conf $zebra_value"
            dns_value=$(awk '/^nameserver/{printf "%s%s", sep, $2; sep=", "} END{print ""}' /etc/resolv.conf)
            log_msg "DNS Servers: $dns_value"
            log_msg "Default IPv4 Route in $CUR_MODE: $(ip route | awk '/^default/ {print $5}')"
            log_msg "Default IPv6 Route in $CUR_MODE: $(ip -6 route | awk '/^default/ {print $5}')"
        fi
    fi

    ########################################
    # 4. Wait for Mode to switch back → EXTENDER
    ########################################
    if [[ "$FAILOVER_DONE" == "true" && "$MODE_EXTENDER_TIME" -eq 0 && "$CUR_MODE" == "EXTENDER" ]]; then
        MODE_EXTENDER_TIME=$(date +%s)
        log_msg "Mode switched: ROUTER → EXTENDER"

        DELTA=$(( MODE_EXTENDER_TIME - GFO_TIME ))
        log_msg "Time (Gw Failover → GW Restore Call) = ${DELTA}s"
    fi

    ########################################
    # 5. STA Ping Restored after Mode EXTENDER
    ########################################
    if [[ "$FAILOVER_DONE" == "true" &&
          $MODE_EXTENDER_TIME -gt 0 &&
          $STA_RESTORE_TIME -eq 0 &&
          "$CUR_STA_PING" == "UP" && "$CUR_MODE" == "EXTENDER" ]]; then

        STA_RESTORE_TIME=$(date +%s)
        log_msg "STA Conn Success"

        DELTA=$(( STA_RESTORE_TIME - MODE_EXTENDER_TIME ))
        log_msg "Time (Mode EXTENDER → STA Conn Success) = ${DELTA}s"
    fi

    ########################################
    # 6. Gateway Restore Detection
    ########################################
    if [[ "$FAILOVER_DONE" == "true" && "$RESTORE_DONE" == "false" &&
          $STA_RESTORE_TIME -gt 0 && "$CUR_MODE" == "EXTENDER" ]]; then

        read G1A G1O G2A G2O <<< "$(get_gateway_status)"

        if [[ "$G1A" == "true" && "$G1O" == "true" &&
              "$G2A" == "false" && "$G2O" == "true" ]]; then

            HB_STATE=$(check_heartbeat)
            if [ "$HB_STATE" = "Available" ]; then
                RESTORE_DONE="true"
                RESTORE_END=$(date +%s)
                # Run restore validation
                verify_restore_conditions RESTORE
                RESULT=$?

                if [[ $RESULT -eq 0 ]]; then
                    TOTAL=$(( RESTORE_END - RESTORE_START ))
                    log_msg "Gateway Restore is Successful. (XLE in GW Mode = ${TOTAL}s)"
                    RESTORE_METHOD=$(safe_dmcli "Device.X_RDK_GatewayManagement.GW_Restore_Method")
                    RESTORE_TIME=$(safe_dmcli "Device.X_RDK_GatewayManagement.DurationOfXLEinGWModeInGFO")
                    log_msg "Gateway Restore Method = $RESTORE_METHOD"
                    log_msg "XLE in GW Mode = ${RESTORE_TIME}s"
                    break
                else
                    log_msg "Gateway Restore Validation Failed"
                fi
            else
                RESTORE_DONE="false"
            fi
        fi
    fi

    sleep 1
done

########################################
# CLEAN & SILENT PROCESS TERMINATION
########################################

# 1. Kill all child background subshells of this script
pkill -P $$ 2>/dev/null

# 2. Kill old instances of this script (except the current one)
for pid in $(pgrep -f "$SCRIPT_NAME"); do
    if [[ "$pid" != "$$" ]]; then
        kill "$pid" 2>/dev/null
    fi
done
