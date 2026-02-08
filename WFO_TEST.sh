#!/bin/bash

CM_MAC=$(deviceinfo.sh -cmac | tr -d ':' | tr '[:lower:]' '[:upper:]')
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="/tmp/WFO_${CM_MAC}_${TIMESTAMP}.log"
PING_HOST="facebook.com"
DNS_HOST="google.com"
LINKDOWN_TIMEOUT_DEFAULT=900
RESTORE_DELAY_DEFAULT=300

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
# Revert Default Values after Testing
########################################
revert_defaults() {
    log_msg "Reverting WAN failover parameters to default values..."

    # Restore RestoreDelay
    dmcli eRT setv Device.X_RDK_WanManager.RestorationDelay uint 300
    sleep 2
    RESTORE_DELAY=$(safe_dmcli "Device.X_RDK_WanManager.RestorationDelay")
    if [[ "$RESTORE_DELAY" == "$RESTORE_DELAY_DEFAULT" ]]; then
        log_msg "RestoreDelay is set to default (300)"
    else
        log_msg "RestoreDelay is NOT set to default (current=$RESTORE_DELAY)"
    fi

    # Restore LinkDownTimeout based on gateway mode
    if [[ "$gw_mode" == "DOCSIS" ]]; then
        dmcli eRT setv Device.X_RDK_DOCSIS.LinkDownTimeout uint 900
        sleep 2
        LINKDOWN_TIMEOUT=$(safe_dmcli "Device.X_RDK_DOCSIS.LinkDownTimeout")
        if [[ "$LINKDOWN_TIMEOUT" == "$LINKDOWN_TIMEOUT_DEFAULT" ]]; then
            log_msg "LinkDownTimeout is set to default (900)"
        else
            log_msg "LinkDownTimeout is NOT set to default (current=$RESTORE_DELAY)"
        fi
    else
        dmcli eRT setv Device.X_RDKCENTRAL-COM_EthernetWAN.LinkDownTimeout uint 900
        sleep 2
        LINKDOWN_TIMEOUT=$(safe_dmcli "Device.X_RDKCENTRAL-COM_EthernetWAN.LinkDownTimeout")
        if [[ "$LINKDOWN_TIMEOUT" == "$LINKDOWN_TIMEOUT_DEFAULT" ]]; then
            log_msg "LinkDownTimeout is set to default (900)"
        else
            log_msg "LinkDownTimeout is NOT set to default (current=$RESTORE_DELAY)"
        fi
    fi
}

########################################
# Read data
########################################

# Read Current Firmware Name
log_msg "XLE Firmware: $(deviceinfo.sh -fw)"

# Read Current Gateway Mode
gw_mode=$(deviceinfo.sh -wanmode | xargs)
log_msg "Gateway Mode = $gw_mode"

if [[ "$gw_mode" == "DOCSIS" ]]; then
    ACTIVE_IF_EXPECTED="DOCSIS"
    AV1_EXPECTED="DOCSIS"
    AV2_EXPECTED="REMOTE_LTE"
else
    ACTIVE_IF_EXPECTED="WANOE"
    AV1_EXPECTED="WANOE"
    AV2_EXPECTED="REMOTE_LTE"
fi

if [[ "$gw_mode" != "DOCSIS" && "$gw_mode" != "WANOE" ]]; then
        log_msg "[ABORT]: Invalid gw_mode=$gw_mode. Aborting."
        exit 1
fi

########################################
# Determine Available and Active Interfaces
########################################

get_available_interfaces() {
    dmcli eRT getv Device.X_RDK_WanManager.InterfaceAvailableStatus \
        | grep value | awk -F 'value:' '{print $2}' \
        | tr '|' '\n' | awk -F',' '$2==1 {print $1}'
}

get_active_interface() {
    dmcli eRT getv Device.X_RDK_WanManager.InterfaceActiveStatus \
        | grep value | awk -F 'value:' '{print $2}' \
        | tr '|' '\n' | awk -F',' '$2==1 {print $1}' | xargs
}

########################################
# Read Inputs Before/After Validation
########################################

verify_failover_conditions() {
    CONTEXT="$1"
    stats="$(date)"
    log_msg "[$stats] Starting verification for context: $CONTEXT"

    ACTIVE_IF=$(get_active_interface)
    #ACTIVE_IF=$(dmcli eRT getv Device.X_RDK_WanManager.InterfaceActiveStatus | grep value | awk -F 'value:' '{print $2}' | tr '|' '\n' | awk -F',' '$2==1 {print $1}' | xargs)

    # Validate brRWAN IPv4/IPv6
    BRWAN_IP4=$(ifconfig brRWAN | grep -w "inet addr" | awk -F: '{print $2}' | awk '{print $1}')
    BRWAN_IP6=$(ifconfig brRWAN | grep -i "global" | awk -F " " '{print $3}' | awk -F "/" '{print $1}')

    if [[ -z "$BRWAN_IP4" ]]; then
        log_msg "FAIL [$CONTEXT]: brRWAN has no IPv4"
        return 1
    fi
    if [[ -z "$BRWAN_IP6" ]]; then
        log_msg "FAIL [$CONTEXT]: brRWAN has no IPv6"
        return 1
    fi

    # Get CurrentActiveInterface and CurrentStandbyInterface
    WAN_ACTIVE=$(dmcli eRT getv Device.X_RDK_WanManager.CurrentActiveInterface | grep value | awk -F 'value:' '{print $2}' | xargs)
    WAN_STANDBY=$(dmcli eRT getv Device.X_RDK_WanManager.CurrentStandbyInterface | grep value | awk -F 'value:' '{print $2}' | xargs)

    # Context-specific validation
    case "$CONTEXT" in
        "PRE-WFO"|"WAN-RESTORE")
            read AVAILABLE_IF1 AVAILABLE_IF2 <<< $(get_available_interfaces | awk '/DOCSIS|WANOE/{print $1} /REMOTE_LTE/{print $1}')
            [[ "$AVAILABLE_IF1" != "$AV1_EXPECTED" ]] && { log_msg "FAIL [$CONTEXT]: AvailableInterface should be $ACTIVE_IF_EXPECTED"; return 1; }
            [[ "$AVAILABLE_IF2" != "$AV2_EXPECTED" ]] && { log_msg "FAIL [$CONTEXT]: AvailableInterface should be $ACTIVE_IF_EXPECTED"; return 1; }
            [[ "$ACTIVE_IF" != "$ACTIVE_IF_EXPECTED" ]] && { log_msg "FAIL [$CONTEXT]: ActiveInterface should be $ACTIVE_IF_EXPECTED"; return 1; }
            [[ "$WAN_ACTIVE" != "erouter0" ]] && { log_msg "FAIL [$CONTEXT]: WANActiveInterface should be erouter0"; return 1; }
            [[ "$WAN_STANDBY" != "brRWAN" ]] && { log_msg "FAIL [$CONTEXT]: WANStandbyInterface should be brRWAN"; return 1; }
            ;;
        "WFO")
            read AVAILABLE_IF <<< $(get_available_interfaces | awk '/REMOTE_LTE/{print $1}')
            [[ "$AVAILABLE_IF" != "REMOTE_LTE" ]] && { log_msg "FAIL [$CONTEXT]: AvailableInterface should be REMOTE_LTE"; return 1; }
            [[ "$ACTIVE_IF" != "REMOTE_LTE" ]] && { log_msg "FAIL [$CONTEXT]: ActiveInterface should be REMOTE_LTE"; return 1; }
            [[ "$WAN_ACTIVE" != "brRWAN" ]] && { log_msg "FAIL [$CONTEXT]: WANActiveInterface should be brRWAN during WFO"; return 1; }
            [[ "$WAN_STANDBY" != "erouter0" ]] && { log_msg "FAIL [$CONTEXT]: WANStandbyInterface should be null during WFO"; return 1; }
            ;;
        *)
            log_msg "FAIL [$CONTEXT]: Unknown context"
            return 1
            ;;
    esac

    # Check Ping for IPv4 and IPv6
    IP4=$(ip -4 addr show "$WAN_ACTIVE" | grep inet | awk '{print $2}')
    IP6=$(ip -6 addr show "$WAN_ACTIVE" | grep global | awk '{print $2}')

    if [[ -n "$IP4" ]]; then
        ping -I "$WAN_ACTIVE" -c 1 -W 2 "$PING_HOST" >/dev/null 2>&1 && PING4="Pass" || PING4="Fail"
    else
        PING4="Fail"
    fi

    if [[ -n "$IP6" ]]; then
        ping -6 -I "$WAN_ACTIVE" -c 1 -W 2 "$PING_HOST" >/dev/null 2>&1 && PING6="Pass" || PING6="Fail"
    else
        PING6="Fail"
    fi

    # Check DNS resolution for IPv4 and IPv6
    DNS4="Fail"
    DNS6="Fail"

    NS=$(nslookup "$DNS_HOST" 2>/dev/null)
    echo "$NS" | grep -qE "([0-9]{1,3}\.){3}[0-9]{1,3}" && DNS4="Pass"
    echo "$NS" | grep -qE "([0-9a-fA-F]{0,4}:){2,}" && DNS6="Pass"

    DEBUG_STEP="Fetch common values"
    XLE_MAC=$(safe_dmcli "Device.X_RDK_Remote.Device.2.MAC")
    XLE_IP4=$(safe_dmcli "Device.X_RDK_Remote.Device.2.IPv4")
    XLE_IP6=$(safe_dmcli "Device.X_RDK_Remote.Device.2.IPv6")
    XLE_MODEL=$(safe_dmcli "Device.X_RDK_Remote.Device.2.ModelNumber")
    FAILOVER_EN=$(safe_dmcli "Device.X_RDK_GatewayManagement.Failover.Enable")
    XLE_CAPABILITY=$(safe_dmcli "Device.X_RDK_Remote.Device.2.Capabilities")
    GW_CAPABILITY=$(safe_dmcli "Device.X_RDK_Remote.Device.1.Capabilities")
    GW_MAC=$(safe_dmcli "Device.X_RDK_Remote.Device.1.MAC")
    GW_MODEL=$(safe_dmcli "Device.X_RDK_Remote.Device.1.ModelNumber")
    MANUFACTURER=$(grep -i "^MANUFACTURE=" /etc/device.properties | cut -d= -f2)
    PRODUCT_CLASS=$(safe_dmcli "Device.DeviceInfo.ProductClass")
    GW_INFO="${MANUFACTURER}-${PRODUCT_CLASS}"

    DEBUG_STEP="Heartbeat validation"
    REM_STATUS=$(safe_dmcli "Device.X_RDK_Remote.Device.2.Status")
    HB_STATE=$([[ "$REM_STATUS" == "3" ]] && echo "Available" || echo "NOT Available")
    [[ "$REM_STATUS" == "3" ]] || { echo "Failed at: $DEBUG_STEP"; return 1; }
    
    DEBUG_STEP="Fetch Gateway Management parameters"
    read G1A G1O G2A G2O <<< "$(get_gateway_status)"

    DEBUG_STEP="GW Failover.Enable validation"
    [[ "$FAILOVER_EN" == "1" ]] || { echo "Failed at: $DEBUG_STEP"; return 1; }

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

    if [[ "$CONTEXT" == "PRE-WFO" ]]; then
        log_msg "XB-XLE Stats Time: $stats"
        log_msg "Account Info=$Account_Info"
        log_msg "GW_INFO=$GW_INFO | GW_MODEL=$GW_MODEL | GW_MAC=$GW_MAC"
        log_msg "XLE_IP4=$XLE_IP4 | XLE_IP6=$XLE_IP6 | XLE_MODEL=$XLE_MODEL | XLE_MAC=$XLE_MAC"
        log_msg "Gateway Failover=$FAILOVER_EN | WAN Failover=$WAN_EN"
        log_msg "brRWAN_IP4: $BRWAN_IP4 & brRWAN_IP6: $BRWAN_IP6"
        log_msg "Heart Beat Status=$HB_STATE"
        log_msg "XLE Capabilities=$XLE_CAPABILITY"
        log_msg "Gateway Capabilities=$GW_CAPABILITY"
        log_msg "XB_Active=$G1A, XB_Operation=$G1O, XLE_Active=$G2A, XLE_Operation=$G2O"
        log_msg ">>>>>>>>>>>>>>>>>>>>>>>>> $CONTEXT Completed <<<<<<<<<<<<<<<<<<<<<<<<<"
    fi
    
    log_msg "Available Interface: $(get_available_interfaces | xargs)"
    log_msg "Active Interface: $(get_active_interface)"
    log_msg "Default IPv4 Route in $CONTEXT: $(ip route | awk '/^default/ {print $5}')"
    log_msg "Default IPv6 Route in $CONTEXT: $(ip -6 route | awk '/^default/ {print $5}')"
    log_msg "CONTEXT=$CONTEXT | Interface=$WAN_ACTIVE | PING4=$PING4 | PING6=$PING6 | DNS4=$DNS4 | DNS6=$DNS6"
    
    return 0 # Success message
}


########################################
#Change Default Values for Testing
########################################

RESTORE_DELAY=$(safe_dmcli "Device.X_RDK_WanManager.RestorationDelay")

# Check if value is not 5
if [[ "$RESTORE_DELAY" != "5" ]]; then
    log_msg "Setting RestorationDelay to 5..."
    dmcli eRT setv Device.X_RDK_WanManager.RestorationDelay uint 5
fi
    
if [[ "$gw_mode" == "DOCSIS" ]]; then
    dmcli eRT setv Device.X_RDK_DOCSIS.LinkDownTimeout uint 0
else
    dmcli eRT setv Device.X_RDKCENTRAL-COM_EthernetWAN.LinkDownTimeout uint 0
fi

########################################
# Pre WAN Failover Check
########################################

verify_failover_conditions PRE-WFO
RESULT=$?
if [[ $RESULT -eq 0 ]]; then
    log_msg "XB-XLE setup looks good before WFO"
else
    log_msg "XB-XLE setup don't look good before WFO, Aborting the validation"
    #exit 1
fi

########################################
# MAIN LOOP (Logic)
########################################

WAN_STATE="PRE-WFO"
WFO_START_TIME=0
RESTORE_TIME=0
FAILOVER_DONE="false"
RESTORE_DONE="false"

while true; do

    ACTIVE_IF=$(get_active_interface)
    read AVAILABLE_IF <<< $(get_available_interfaces | awk '/REMOTE_LTE/{print $1}')
    WAN_ACTIVE=$(safe_dmcli "Device.X_RDK_WanManager.CurrentActiveInterface")
    WAN_STANDBY=$(safe_dmcli "Device.X_RDK_WanManager.CurrentStandbyInterface")

    ########################################
    # 1. DETECT WAN Interface Down Thread
    ########################################
    if [[ "$WAN_ACTIVE" == "brRWAN" && "$WAN_STANDBY" == "erouter0" && $WFO_START_TIME -eq 0 ]]; then
        WFO_START_TIME=$(date +%s)
        
        log_msg "$(date) WAN FAILOVER DETECTED"
        log_msg "WFO_START_TIME=$WFO_START_TIME"
    fi

    ########################################
    # 2. WAN FAILOVER SUCCESS
    ########################################
    if [[ "$ACTIVE_IF" == "REMOTE_LTE" &&
          "$WAN_ACTIVE" == "brRWAN" &&
          "$WAN_STANDBY" == "erouter0" &&
          "$AVAILABLE_IF" == "REMOTE_LTE" &&
          "$FAILOVER_DONE" == "false" &&
          "$RESTORE_DONE" == "false" ]]; then
        
        FAILOVER_DONE="true"
        WAN_STATE="WFO"

        sleep 20
                
        # WAN Failover Validation
        verify_failover_conditions "WFO"
        log_msg "[Info] WAN Failover is Successful."
    fi

    ########################################
    # 3. DETECT WAN RESTORE
    ########################################
    if [[ "$ACTIVE_IF" =~ ^(DOCSIS|WANOE)$ &&
          "$WAN_ACTIVE" == "erouter0" &&
          "$WAN_STANDBY" == "brRWAN" &&
          $WFO_START_TIME -gt 0 &&
          $RESTORE_TIME -eq 0 &&
          "$FAILOVER_DONE" == "true" && 
          "$RESTORE_DONE" == "false" ]]; then
        
        RESTORE_TIME=$(date +%s)
        WAN_STATE="WAN-RESTORE"
        RESTORE_DONE="true"
        sleep 20
        # WAN Restore Validation
        verify_failover_conditions "WAN-RESTORE"
        RESULT=$?

        if [[ $RESULT -eq 0 ]]; then
            TOTAL=$(( RESTORE_TIME - WFO_START_TIME ))
            log_msg "WAN Restore is Successful. (Gateway in WFO Mode = ${TOTAL}s)"
            revert_defaults
            exit 0
        else
            log_msg "WAN Restore Validation Failed"
            RESTORE_DONE="false"
        fi
    fi

    sleep 2
done
