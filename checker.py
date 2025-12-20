import os
import sys
import json
import base64
import requests
import subprocess
import time
import random
import shutil
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
XRAY_BIN = "./xray"  # Assumes xray is in current dir
CHECK_URL = "https://checkip.amazonaws.com" # No captcha, just IP
TIMEOUT = 10 # Seconds for curl/connect (Increased from 6)
MAX_THREADS = 200 # Faster scraping
BASE_PORT = 20000

# ... (rest of config)

# ... (inside check_proxy function)

        else:
            # 4. Curl check
            # curl -x socks5h://127.0.0.1:PORT
            chk_cmd = [
                "curl", "-s", "--connect-timeout", "5", "--max-time", "8",
                "-x", f"socks5h://127.0.0.1:{local_port}",
                CHECK_URL
            ]
            
            try:
                # We look for a 200 OK or just successful exit code with body content
                result = subprocess.run(chk_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                # checkip.amazonaws.com returns just an IP (e.g. 12 chars). 100 bytes is too much.
                if result.returncode == 0 and len(result.stdout) > 6:
                    # Valid IP is at least 7 chars (1.1.1.1), allow loose > 6
                    success = True
                else:
                    success = False
                    # Debug curl failure occasionally - silenced
                    if thread_id == 0 and random.random() < 0.05:
                         pass
                         # print(f"[DEBUG] Curl failed. Return: {result.returncode}, Stdout len: {len(result.stdout)}")
            except Exception:
                success = False
            
    except Exception as e:
        print(f"[DEBUG] Exception checking proxy: {e}")
        success = False
    finally:
        # Cleanup
        if 'proc' in locals() and proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        
        if os.path.exists(config_file):
            try:
                os.remove(config_file)
            except: pass
            
    return success, link


def fetch_proxies():
    print("Fetching new proxies from sources...")
    links = set()
    
    # 4 sources requested by user
    urls = [
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vm.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/tr.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/ss.txt"
    ]
    
    for url in urls:
        print(f"Fetching {url}")
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                
                # Check for "Mojibake" or base64 decoding if needed (skipped as file seems plain or line-based)
                # Some files might be base64 blobs, simple heuristic:
                if "vless://" not in content and "vmess://" not in content and "trojan://" not in content and "ss://" not in content:
                     try:
                         # Try decoding entire body
                         decoded = base64.b64decode(content).decode('utf-8')
                         content = decoded
                     except: pass
                
                for line in content.splitlines():
                    line = line.strip()
                    if line and (
                        line.startswith("vless://") or
                        line.startswith("vmess://") or
                        line.startswith("trojan://") or
                        line.startswith("ss://")
                    ):
                        links.add(line)
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
            
    return list(links)

def load_queue():
    if os.path.exists(QUEUE_FILE):
        try:
            with open(QUEUE_FILE, 'r') as f:
                lines = []
                for l in f.readlines():
                    l = l.strip()
                    if l and (
                        l.startswith("vless://") or 
                        l.startswith("vmess://") or
                        l.startswith("trojan://") or
                        l.startswith("ss://")
                    ):
                        lines.append(l)
            if lines:
                print(f"Loaded {len(lines)} proxies from queue file.")
                return lines
        except Exception as e:
            print(f"Error loading queue: {e}")
    return []

def save_queue(proxies):
    # Overwrite the queue file with remaining proxies
    with open(QUEUE_FILE, 'w') as f:
        f.write("\n".join(proxies))
    print(f"Saved {len(proxies)} proxies back to queue file.")

def save_distributed(proxies):
    # Distribute proxies into 10 files
    # Requirement: Avoid duplicates across ALL 10 lists
    
    os.makedirs("proxy_lists", exist_ok=True)
    
    # 1. Read existing proxies from all 10 files to strict deduplication set
    existing_proxies = set()
    for i in range(1, TOTAL_OUTPUT_LISTS + 1):
        fname = f"proxy_lists/list_{i}.txt"
        if os.path.exists(fname):
            try:
                with open(fname, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line: existing_proxies.add(line)
            except: pass

    # 2. Filter new proxies
    unique_new_proxies = [p for p in proxies if p not in existing_proxies]
    
    if not unique_new_proxies:
        print("No new unique proxies to save (all duplicates).")
        return

    # 3. Append to files round-robin
    files = {}
    try:
        for i in range(1, TOTAL_OUTPUT_LISTS + 1):
            files[i] = open(f"proxy_lists/list_{i}.txt", "a")

        for idx, proxy in enumerate(unique_new_proxies):
            file_idx = (idx % TOTAL_OUTPUT_LISTS) + 1
            files[file_idx].write(proxy + "\n")
            # Update local set to prevent dupes within this batch if any (though input 'proxies' is already unique)
            
    finally:
        for f in files.values():
            f.close()
            
    print(f"Distributed {len(unique_new_proxies)} UNIQUE proxies into {TOTAL_OUTPUT_LISTS} files in 'proxy_lists/'")

def save_general(proxies):
    # Save all found proxies to a single general list
    # We append to it, but we could also deduplicate against it if we read it first.
    # For simplicity and speed, let's just append updates.
    
    if not proxies: return

    # Simple deduplication against file content could be expensive if large, 
    # but let's try to be clean.
    existing = set()
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, 'r') as f:
                for line in f:
                    existing.add(line.strip())
        except: pass
        
    new_unique = [p for p in proxies if p not in existing]
    
    print(f"DEBUG: Found {len(proxies)} proxies to save. {len(new_unique)} are new unique.")

    if new_unique:
        try:
            with open(RESULTS_FILE, 'a') as f:
                for p in new_unique:
                    f.write(p + "\n")
            print(f"Saved {len(new_unique)} new proxies to general list '{RESULTS_FILE}'")
        except Exception as e:
            print(f"ERROR: Failed to write to {RESULTS_FILE}: {e}")
    else:
        print("No new proxies for general list.")

def main():
    start_time = time.time()
    
    if not shutil.which(XRAY_BIN) and not os.path.exists(XRAY_BIN):
        # On Github Actions or Linux, we might need to download xray if not present
        pass
        # print(f"Error: {XRAY_BIN} not found. Please install Xray-core.")
        # sys.exit(1)

    # 1. Load Proxies (Queue + Fetch)
    queue_links = load_queue()
    fetched_links = fetch_proxies()
    
    # Combine and deduplicate
    all_links = list(set(queue_links + fetched_links))
    
    # ----------------------------------------------------
    # DEDUPLICATION AGAINST EXISTING RESULTS
    # ----------------------------------------------------
    # We want to avoid checking proxies we ALREADY have in our lists (list_1..20.txt)
    # This prevents the list from growing with duplicates every run.
    
    print("Loading existing proxies to skip duplicates...")
    existing_proxies = set()
    # Check general list
    if os.path.exists(RESULTS_FILE):
        try:
             with open(RESULTS_FILE, 'r') as f:
                 for line in f: existing_proxies.add(line.strip())
        except: pass

    # Check distributed lists
    for i in range(1, 21): # Assuming 20 lists max (can be dynamic or constant)
        fname = f"proxy_lists/list_{i}.txt"
        if os.path.exists(fname):
            try:
                with open(fname, 'r') as f:
                    for line in f: existing_proxies.add(line.strip())
            except: pass
            
    original_count = len(all_links)
    all_links = [l for l in all_links if l not in existing_proxies]
    print(f"Deduplication: Removed {original_count - len(all_links)} proxies already in lists. Remaining: {len(all_links)}")

    # Shuffle for randomness
    random.shuffle(all_links)
    
    # Cap total proxies to check to prevent extreme runtimes or memory usage
    if len(all_links) > 10000:
        print(f"Capping total proxies from {len(all_links)} to 10000.")
        all_links = all_links[:10000]
    
    print(f"Total proxies to check: {len(all_links)}")
    if len(all_links) == 0:
        print("No NEW proxies to check (all found are duplicates).")
        return

    working_proxies = []
    checked_count = 0
    
    remaining_links = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Create a dict to map future to link
        future_to_link = {}
        
        link_iterator = iter(all_links)
        exhausted = False
        
        while len(working_proxies) < TARGET_WORKING_COUNT and not exhausted:
            # Check Time Limit
            if time.time() - start_time > MAX_RUNTIME:
                print(f"Time limit reached ({MAX_RUNTIME}s). Stopping early to save state.")
                break

            # Fill up the pool
            while len(future_to_link) < MAX_THREADS * 2:
                try:
                    link = next(link_iterator)
                    future = executor.submit(check_proxy, link, len(future_to_link) % MAX_THREADS)
                    future_to_link[future] = link
                except StopIteration:
                    exhausted = True
                    break
            
            if not future_to_link:
                break
                
            # Process completed (with time check in loop)
            # We use a trick to poll: wait small amount or just check done
            
            # Simple check: peek at futures
            if not future_to_link:
                break
                
            # Wait for at least one, with timeout
            try:
                # Get the first completed from the current set
                for future in as_completed(future_to_link.keys(), timeout=1):
                    result_success, result_link = future.result()
                    checked_count += 1
                    
                    if result_success:
                        working_proxies.append(result_link)
                        print(f"[{len(working_proxies)}/{TARGET_WORKING_COUNT}] FOUND: {result_link[:30]}...")
                    
                    del future_to_link[future]
                    
                    # Exit conditions
                    if len(working_proxies) >= TARGET_WORKING_COUNT:
                        break
                    if time.time() - start_time > MAX_RUNTIME:
                        break
            except Exception:
                # Timeout on as_completed (no proxy finished in 1s), just continue loop to check time
                pass

            if len(working_proxies) >= TARGET_WORKING_COUNT:
                print("Target working count reached.")
                break
            
        # Collect remaining from iterator
        current_processing = list(future_to_link.values()) 
        # Recover unchecked links from futures (if we didn't wait for them)
        remaining_links = list(future_to_link.values()) + list(link_iterator)
            
    # Save Results
    if working_proxies:
        save_distributed(working_proxies)
        save_general(working_proxies)

    # Save Queue State (unchecked proxies)
    if not remaining_links and exhausted and not future_to_link:
        print("Queue exhausted. Deleting queue file to fetch fresh next time.")
        if os.path.exists(QUEUE_FILE):
            os.remove(QUEUE_FILE)
    else:
        # Check specific condition: if we found some working but ran out of time, 
        # we still want to continue checking the rest next time
        save_queue(remaining_links)

if __name__ == "__main__":
    main()
