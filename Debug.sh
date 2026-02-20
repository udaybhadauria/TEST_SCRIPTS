#!/bin/sh

# Interval and duration
INTERVAL=600              # 10 minutes
DURATION=$((3*60*60))     # 3 hours
ITERATIONS=$((DURATION/INTERVAL))

# Logs
LOG="/tmp/system_process_health.log"
SUMMARY="/tmp/system_process_summary.log"

# Process patterns to monitor
PATTERNS="Ccsp|Agent|telemetry|mesh|OneWifi|manager|gateway|mgr"

echo "Starting Important Process Health Monitoring..." > $LOG
echo "Duration: 3 Hours (10 min interval)" >> $LOG
echo "--------------------------------------------------" >> $LOG

COUNT=1

while [ $COUNT -le $ITERATIONS ]
do
    TIMESTAMP=$(date)
    echo "==================================================" >> $LOG
    echo "Iteration: $COUNT  Time: $TIMESTAMP" >> $LOG
    echo "==================================================" >> $LOG

    for PID in $(ls /proc | grep '^[0-9]*$')
    do
        [ -f /proc/$PID/status ] || continue

        # Get process name
        NAME=$(grep "^Name:" /proc/$PID/status | awk '{print $2}')

        # Skip kernel threads (names in brackets)
        case "$NAME" in
            [*]) continue ;;
        esac

        # Only match important patterns
        echo "$NAME" | grep -Ei "$PATTERNS" >/dev/null 2>&1 || continue

        # Process info
        STATE=$(grep "^State:" /proc/$PID/status | awk '{print $2}')
        RSS=$(grep "VmRSS:" /proc/$PID/status | awk '{print $2}')
        VSZ=$(grep "VmSize:" /proc/$PID/status | awk '{print $2}')
        FD_COUNT=$(ls /proc/$PID/fd 2>/dev/null | wc -l)

        # Skip if RSS empty or zero
        [ -z "$RSS" ] && RSS=0

        # Zombie check
        [ "$STATE" = "Z" ] && ZOMBIE="YES" || ZOMBIE="NO"

        # D state check
        [ "$STATE" = "D" ] && D_PROCESS="YES" || D_PROCESS="NO"

        echo "PID:$PID Name:$NAME RSS:${RSS}KB VSZ:${VSZ}KB FD:$FD_COUNT State:$STATE Zombie:$ZOMBIE D-State:$D_PROCESS" >> $LOG
    done

    sleep $INTERVAL
    COUNT=$((COUNT+1))
done

echo "Monitoring Completed."
echo "Detailed Log: $LOG"
