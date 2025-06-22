#!/bin/bash

NUM_RUNS=${1:-5}
PYTHON_SCRIPT="udp_holepunch.py"

# Create results directory and unique subdirectory for this batch
RESULTS_DIR="holepunch_results"
mkdir -p "$RESULTS_DIR"
RUN_ID=$(date +"%Y%m%d_%H%M%S")
BATCH_DIR="$RESULTS_DIR/$RUN_ID"
mkdir -p "$BATCH_DIR"

echo "Storing results in $BATCH_DIR"

for mode in remote local ; do
  echo "Running $mode test for $NUM_RUNS runs..."
  OUTFILE="$BATCH_DIR/holepunch_${mode}_raw.txt"
  > $OUTFILE
  for i in $(seq 1 $NUM_RUNS); do
    OUTJSON="$BATCH_DIR/${mode}_run_${i}.json"
    if [ "$mode" = "local" ]; then
      OUTPUT=$(modal run $PYTHON_SCRIPT --local --output-path $OUTJSON)
    else
      OUTPUT=$(modal run $PYTHON_SCRIPT --output-path $OUTJSON)
    fi
    # Save full output for debugging
    echo "$OUTPUT" >> $OUTFILE
  done
done

# Create a CSV summary with the requested columns
CSVFILE="$BATCH_DIR/holepunch_summary.csv"
echo "mode,test_id,run_num,success,success_endpoint_a,success_endpoint_b,endpoint_infos_a,endpoint_infos_b,region_a,region_b,hairpin_supported_a,hairpin_supported_b,quic_avg_latency,quic_min_latency,quic_max_latency,quic_samples,error" > $CSVFILE

for mode in remote local; do
  for i in $(seq 1 $NUM_RUNS); do
    JSONFILE="$BATCH_DIR/${mode}_run_${i}.json"
    if [ ! -f "$JSONFILE" ]; then continue; fi
    endpoint_a=$(jq -c '.success_endpoint_a // empty' "$JSONFILE")
    endpoint_b=$(jq -c '.success_endpoint_b // empty' "$JSONFILE")
    endpoint_infos_a=$(jq -c '.registration.self.endpoint_infos // empty' "$JSONFILE")
    endpoint_infos_b=$(jq -c '.registration.peer.endpoint_infos // empty' "$JSONFILE")
    region_a=$(jq -r '.registration.self.region // empty' "$JSONFILE")
    region_b=$(jq -r '.registration.peer.region // empty' "$JSONFILE")
    # Extract hairpin_supported as semicolon-separated list for A and B
    hairpin_supported_a=$(jq -r '.registration.self.endpoint_infos | map(.hairpin_supported) | join(";")' "$JSONFILE")
    hairpin_supported_b=$(jq -r '.registration.peer.endpoint_infos | map(.hairpin_supported) | join(";")' "$JSONFILE")
    success_a=$(jq '.success_endpoint_a != null' "$JSONFILE")
    success_b=$(jq '.success_endpoint_b != null' "$JSONFILE")
    success="false"
    if [ "$success_a" = "true" ] && [ "$success_b" = "true" ]; then
      success="true"
    fi
    # QUIC test results (from B's output)
    quic_avg_latency=""
    quic_min_latency=""
    quic_max_latency=""
    quic_samples=""
    latencies=$(jq '.quic_results.latencies // empty' "$JSONFILE")
    if [ "$latencies" != "" ] && [ "$latencies" != "null" ]; then
      quic_samples=$(jq '.quic_results.latencies | length' "$JSONFILE")
      quic_avg_latency=$(jq '.quic_results.latencies | if length > 0 then (add/length) else null end' "$JSONFILE")
      quic_min_latency=$(jq '.quic_results.latencies | min' "$JSONFILE")
      quic_max_latency=$(jq '.quic_results.latencies | max' "$JSONFILE")
    fi
    error=$(jq -r '.error // empty' "$JSONFILE")
    echo "$mode,$RUN_ID,$i,$success,$endpoint_a,$endpoint_b,$endpoint_infos_a,$endpoint_infos_b,$region_a,$region_b,$hairpin_supported_a,$hairpin_supported_b,$quic_avg_latency,$quic_min_latency,$quic_max_latency,$quic_samples,$error" >> $CSVFILE
  done
done

echo "Summary table written to $CSVFILE"