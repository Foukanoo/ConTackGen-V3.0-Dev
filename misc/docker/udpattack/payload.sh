#!/bin/bash

DURATION=60
OUTPUT_PATH=/data/capture
MITM_SERVER_ADDRESS=localhost
MITM_SERVER_PORT=8080
MITM_PROXY_PORT=9090

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--duration)
            DURATION="$2"
            shift
            shift
            ;;
        -o|--output)
            OUTPUT_PATH="$2"
            shift
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -d, --duration <duration>  Duration of the capture (default: 60 seconds)"
            echo "  -o, --output <output>      Base output file path without extension (default: /data/capture)"
            echo "  -h, --help                 Show this help message"
            exit 0
            ;;
        *)
            echo "Invalid option: $1"
            echo "See --help for more information"
            exit 1
            ;;
    esac
done

PCAP_OUTPUT="${OUTPUT_PATH}.pcap"
echo "Entrypoint arguments:"
echo "  Duration:   $DURATION"
echo "  Output PCAP: $PCAP_OUTPUT"
echo "  Interface:  eth0"
echo ""

echo "Creating output directory: $(dirname $PCAP_OUTPUT)"
mkdir -p $(dirname $PCAP_OUTPUT)

# Vérifier le type d'attaque
if [ "$ATTACK_TYPE" = "MITM" ]; then
    # Mode MITM
    echo "Starting MITM scenario..."
    python3 -m http.server ${MITM_SERVER_PORT} &
    SERVER_PID=$!
    echo "Local HTTP server started on port ${MITM_SERVER_PORT} with PID $SERVER_PID"

    java -cp /app/MITMAttack.jar fr.contacgen.MITMAttack ${MITM_SERVER_ADDRESS} ${MITM_SERVER_PORT} ${MITM_PROXY_PORT} ${DURATION} &
    MITM_PID=$!
    echo "MITM attack started (PID: $MITM_PID)"

    # Lancer la capture
    tshark -i eth0 -a duration:${DURATION} -w ${OUTPUT_PATH}.pcapng &
    TSHARK_PID=$!
    echo "tshark started with PID $TSHARK_PID"

    sleep 2

    END=$(( $(date +%s) + DURATION ))
    echo "Generating traffic (HTTP via MITM) for ${DURATION} seconds..."
    while [ $(date +%s) -lt $END ]; do
        curl -s "http://localhost:${MITM_PROXY_PORT}?msg=Client" > /dev/null
        sleep 1
    done

    wait $TSHARK_PID

    tcpdump -r ${OUTPUT_PATH}.pcapng -w ${PCAP_OUTPUT}
    chmod a+r $PCAP_OUTPUT
    echo "Capture finished, file saved to $PCAP_OUTPUT"

    kill $SERVER_PID
    kill $MITM_PID || true

else
    # Mode UDPDOS
    echo "Starting UDPDOS scenario..."
    # Ici, vous pouvez juste lancer tshark, et l'UDPDos sera exécuté par le code Java.
    # Pas de serveur HTTP ni de curl dans ce mode.

    tshark -i eth0 -a duration:${DURATION} -w ${OUTPUT_PATH}.pcapng &
    TSHARK_PID=$!
    echo "tshark started with PID $TSHARK_PID"

    # Attendre la fin
    wait $TSHARK_PID

    tcpdump -r ${OUTPUT_PATH}.pcapng -w ${PCAP_OUTPUT}
    chmod a+r $PCAP_OUTPUT
    echo "Capture finished, file saved to $PCAP_OUTPUT"
fi

exit 0
