#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

CLIENTS=50000
RATE_SUSTAINED=1000
RATE_BURST=0  # unlimited

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

header() { echo -e "\n${BOLD}${CYAN}$1${NC}\n"; }
label()  { echo -e "${BOLD}$1${NC}"; }

# ─── Memory sampling (leak-regression guard) ─────────────────────────
# Sample a process's RSS (KB) once per second to a file until it exits.
# Run in the background during a load test, then summarize the trajectory.
sample_mem() { # pid outfile
    local pid="$1" out="$2"
    : > "$out"
    while kill -0 "$pid" 2>/dev/null; do
        echo "$(date +%s) $(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')" >> "$out"
        sleep 1
    done
}

# Print start / peak / end / drift for a sampled RSS trajectory. A large positive
# drift under a bounded (renewal / fixed-client) workload signals a possible leak.
mem_summary() { # outfile
    awk '
        $2!=""{ if(n==0)s=$2; e=$2; if($2>mx)mx=$2; n++ }
        END{
            if(n==0){ printf "    mem: (no samples)\n"; exit }
            printf "    mem: start=%dKB  peak=%dKB  end=%dKB  drift=%+dKB  over %ds\n", s, mx, e, e-s, n-1
        }' "$1"
}

kill_dhcp() {
    sudo pkill -f "rdhcpd.*bench" 2>/dev/null || true
    sudo pkill -f "kea-dhcp4.*bench" 2>/dev/null || true
    sleep 0.5
}

# ─── Setup ───────────────────────────────────────────────────────────
header "═══ rDHCP vs Kea — Side-by-Side Benchmark ═══"

echo "Building rdhcpd release..."
cd "$PROJECT_DIR"
cargo build --release --bin rdhcpd 2>&1 | tail -1

# Add loopback address for subnet matching
if ! ip addr show lo | grep -q "10.0.0.1"; then
    echo "Adding 10.0.0.1/8 to loopback..."
    sudo ip addr add 10.0.0.1/8 dev lo 2>/dev/null || true
fi

kill_dhcp

# ─── Function to run a test ──────────────────────────────────────────
run_test() {
    local test_name="$1"
    local rate="$2"
    local count="$3"
    local clients="$4"

    label "$test_name"
    echo "  rate=$rate  count=$count  clients=$clients"
    echo ""

    # --- rDHCP ---
    rm -rf /tmp/rdhcpd-bench; mkdir -p /tmp/rdhcpd-bench/leases
    sudo RUST_LOG=warn "$PROJECT_DIR/target/release/rdhcpd" "$SCRIPT_DIR/config.toml" &
    RDHCP_PID=$!
    sleep 1

    if ! kill -0 $RDHCP_PID 2>/dev/null; then
        echo "  ERROR: rdhcpd failed to start"
        return
    fi

    echo -e "  ${GREEN}rDHCP:${NC}"
    sample_mem "$RDHCP_PID" /tmp/rdhcpd-bench/mem.dat &
    local RDHCP_SAMPLER=$!
    sudo perfdhcp -4 -r "$rate" -n "$count" -R "$clients" -l lo 10.0.0.1 2>&1 | \
        grep -E "sent|received|drops|min|avg|max|Rate" | sed 's/^/    /' || true
    kill "$RDHCP_SAMPLER" 2>/dev/null; wait "$RDHCP_SAMPLER" 2>/dev/null || true

    # Memory: final snapshot + trajectory over the load (leak-regression guard)
    RDHCP_RSS=$(ps -o rss= -p $RDHCP_PID 2>/dev/null | tr -d ' ')
    echo "    RSS (final): ${RDHCP_RSS:-?} KB"
    mem_summary /tmp/rdhcpd-bench/mem.dat

    sudo kill $RDHCP_PID 2>/dev/null; wait $RDHCP_PID 2>/dev/null || true
    sleep 0.5

    # --- Kea ---
    rm -rf /tmp/kea-bench; mkdir -p /tmp/kea-bench
    sudo kea-dhcp4 -c "$SCRIPT_DIR/kea-config.json" &
    KEA_PID=$!
    sleep 2  # Kea takes longer to start

    if ! kill -0 $KEA_PID 2>/dev/null; then
        echo "  ERROR: kea-dhcp4 failed to start"
        return
    fi

    echo -e "  ${RED}Kea:${NC}"
    sample_mem "$KEA_PID" /tmp/kea-bench/mem.dat &
    local KEA_SAMPLER=$!
    sudo perfdhcp -4 -r "$rate" -n "$count" -R "$clients" -l lo 10.0.0.1 2>&1 | \
        grep -E "sent|received|drops|min|avg|max|Rate" | sed 's/^/    /' || true
    kill "$KEA_SAMPLER" 2>/dev/null; wait "$KEA_SAMPLER" 2>/dev/null || true

    # Memory: final snapshot + trajectory over the load
    KEA_RSS=$(ps -o rss= -p $KEA_PID 2>/dev/null | tr -d ' ')
    echo "    RSS (final): ${KEA_RSS:-?} KB"
    mem_summary /tmp/kea-bench/mem.dat

    sudo kill $KEA_PID 2>/dev/null; wait $KEA_PID 2>/dev/null || true
    sleep 0.5

    echo ""
}

# ─── Cleanup on exit ─────────────────────────────────────────────────
cleanup() {
    echo ""
    kill_dhcp
}
trap cleanup EXIT

# ─── Tests ────────────────────────────────────────────────────────────
header "Test 1: Sustained Load (${RATE_SUSTAINED} DORA/sec)"
run_test "Sustained ${RATE_SUSTAINED}/sec" "$RATE_SUSTAINED" 10000 10000

header "Test 2: Burst (max rate, ${CLIENTS} clients)"
run_test "Burst max-rate" "$RATE_BURST" "$CLIENTS" "$CLIENTS"

header "Test 3: Renewal Storm (1k clients, 10x each)"
run_test "Renewal storm" "$RATE_BURST" 10000 1000

header "═══ Benchmark Complete ═══"
