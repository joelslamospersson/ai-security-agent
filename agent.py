import sys
import os
import json
import time
import logging

# --------
# AI Security Agent
# Monitors logs, network events, and system activity
# Detects potential threats and performs automated responses
# --------

# Configuration file
CONFIG_FILE = ".env"
DEBUG_MODE = True  # Set to False in production

# Agent data storage
BAN_LIST = "data/ban_list.json"
WHITELIST = "data/whitelist.json"
QUARANTINE_LIST = "data/quarantine_list.json"
IP_REPUTATION_LIST = "data/ip_reputation_list.json"

# Training / detection data
PATTERN_LIST = "data/training/pattern_list.json"
BOTNET_SIGNATURES = "data/training/botnet_signatures.json"

# Other data
DISCORD_WEBHOOKS = "data/discord_webhooks.json"
# Logs
AGENT_LOGS = "agent.log"

settings = {}

# --------------------------
# Logging configuration
# ---------------------------
logging.basicConfig(
    filename=AGENT_LOGS,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ---------------------
# Utility Functions
# ---------------------
def load_json(file):

    # Create file if missing
    if not os.path.exists(file):
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, "w") as f:
            json.dump({}, f)

    # Load JSON data from file, handle empty file and invalid JSON
    # Prevents crashes and resets file if corrupted
    try:
        with open(file, "r") as f:
            data = f.read().strip()

            # Handle empty file
            if not data:
                return {}

            return json.loads(data)

    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in {file}, resetting file.")
        save_json(file, {})  # Reset file to empty JSON
        return {}

def save_json(file, data):
    # Save JSON data to file
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# ----------------------
# Brain analysis logic
# ------------------------
def brain(event):
    logging.info(f"Analyzing event: {event}")

    patterns = load_json(PATTERN_LIST)

    # Check for known patterns in the event
    for p, data in patterns.items():
        if p.lower() in event.lower():
            logging.warning(f"Pattern detected: {p}")
            return {
                "threat": True,
                "pattern": p,
                "response": data["response"],
            }
        
    return {
        "threat": False
    }

# ----------------------
# Action execution logic
# ----------------------
def actions(result, source_ip=None):

    if not result["threat"]:
        # Temp log message ( deBug )
        if DEBUG_MODE:
            logging.info("No threat detected, no action needed.")
        return
    
    # Add ip to ban list and log the action
    banlist = load_json(BAN_LIST)

    # Add source IP to ban list if available
    if source_ip:
        banlist[source_ip] = {
            "reason": result["pattern"],
            "timestamp": time.time()
        }
        save_json(BAN_LIST, banlist)
        logging.info(f"IP {source_ip} added to ban list for reason: {result['pattern']}")

# ----------------------
# Event monitoring logic ( loop )
# -----------------------
def monitor():

    while True:
        event = "Simulated event data"  # Placeholder for actual event data

        logging.info("Monitoring for events...")
        result = brain(event)
        actions(result, source_ip="192.168.1.55")  # Placeholder for actual source IP
        time.sleep(5)  # Sleep for a while before checking for new events

# -----------------------
# Main function
# -----------------------
def main():
    print("Starting AI-Security Agent ...")
    logging.info("AI-Security Agent started.")

    # Start monitoring for events
    monitor()

# -----------------------
# Run the main function
# -----------------------
if __name__ == "__main__":
    main()
