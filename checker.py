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
TIMEOUT = 10 # Seconds for curl/connect
MAX_THREADS = 200 # Faster scraping
BASE_PORT = 20000

# Staged Execution Config
TARGET_WORKING_COUNT = 50000 # Stop after finding this many working proxies
MAX_RUNTIME = 1750 # Seconds (approx 29 mins) to match 30m schedule
QUEUE_FILE = "proxies_queue.txt" # File to store unchecked proxies
RESULTS_FILE = "proxy_list_found.txt" # File to store working proxies (appended or overwritten)
TOTAL_OUTPUT_LISTS = 5 # Number of separate lists to distribute proxies into

def parse_vmess(link):
    """Parse vmess:// link to Xray outbound config object."""
    try:
        data = link[8:] # strip vmess://
        # Try decoding base64
        try:
            decoded = base64.b64decode(data).decode('utf-8')
            json_config = json.loads(decoded)
            
            # Extract fields from standard vmess json
            add = json_config.get("add")
            port = int(json_config.get("port", 0))
            uuid = json_config.get("id")
            aid = int(json_config.get("aid", 0))
            net = json_config.get("net", "tcp")
            path = json_config.get("path", "")
            host = json_config.get("host", "")
            if not (add and port and uuid): return None
            
            stream_settings = {
                "network": net,
            }
            if net == "ws":
                stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": add,
                        "port": port,
                        "users": [{"id": uuid, "alterId": aid}]
                    }]
                },
                "streamSettings": stream_settings
            }

        except Exception:
            return None
    except Exception as e:
        return None

def parse_vless(link):
    """Parse vless://uuid@host:port?params#name"""
    try:
        # vless://uuid@host:port?query
        parse = urllib.parse.urlparse(link)
        if parse.scheme != "vless": return None
        
        uuid = parse.username
        host = parse.hostname
        port = parse.port
        params = urllib.parse.parse_qs(parse.query)
        
        if not (uuid and host and port): return None

        net = params.get("type", ["tcp"])[0]
        path = params.get("path", [""])[0]
        encryption = params.get("encryption", ["none"])[0]
        
        stream_settings = {"network": net}
        if net == "ws":
             stream_settings["wsSettings"] = {"path": path}
        
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uuid, "encryption": encryption}]
                }]
            },
            "streamSettings": stream_settings
        }
    except Exception:
        return None

def parse_trojan(link):
    """Parse trojan://password@host:port?params#name"""
    try:
        parse = urllib.parse.urlparse(link)
        if parse.scheme != "trojan": return None
        
        password = parse.username
        host = parse.hostname
        port = parse.port
        
        if not (password and host and port): return None
        
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": host, "port": port, "password": password}]
            }
        }
    except Exception:
        return None

def parse_ss(link):
    """Parse ss://base64(method:password)@host:port"""
    try:
        # ss://BASE64@HOST:PORT
        # or ss://method:pass@host:port
        data = link[5:]
        if '@' not in data: return None
        
        user_info, host_info = data.rsplit('@', 1)
        
        # Try generic decode
        try:
            # Fix padding
            padding = len(user_info) % 4
            if padding: user_info += '=' * (4 - padding)
            decoded_user = base64.urlsafe_b64decode(user_info).decode('utf-8')
            if ':' in decoded_user:
                method, password = decoded_user.split(':', 1)
            else:
                return None
        except:
             # Maybe it's plain text ss://method:pass@...
             if ':' in user_info:
                 method, password = user_info.split(':', 1)
             else:
                 return None

        host, port_str = host_info.split(':', 1)
        # remove tag if present
        if '#' in port_str: port_str = port_str.split('#')[0]
        port = int(port_str)

        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{"address": host, "port": port, "method": method, "password": password}]
            }
        }
    except Exception:
        return None

def parse_http(link):
    """Parse http:// or https:// link."""
    try:
        parse = urllib.parse.urlparse(link)
        if parse.scheme not in ["http", "https"]: return None
        if not parse.hostname or not parse.port: return None
        # Return the original link or cleaned version for curl -x
        return {"protocol": parse.scheme, "link": link}
    except Exception:
        return None

def generate_config(outbound, local_port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }

def check_proxy(link, thread_id):
    """Checks a single proxy link."""
    local_port = BASE_PORT + thread_id
    config_file = f"config_{local_port}.json"
    
    # 1. Parse
    outbound = None
    is_direct_check = False
    proxy_type = ""
    
    if link.startswith("vmess://"): outbound = parse_vmess(link)
    elif link.startswith("vless://"): outbound = parse_vless(link)
    elif link.startswith("trojan://"): outbound = parse_trojan(link)
    elif link.startswith("ss://"): outbound = parse_ss(link)
    elif link.startswith("http://") or link.startswith("https://"):
        outbound = parse_http(link)
        is_direct_check = True
        proxy_type = "http"
    elif link.startswith("socks5://"):
        # We can reuse parse_http logic for socks5:// URL structure
        outbound = parse_http(link.replace("socks5://", "http://"))
        is_direct_check = True
        proxy_type = "socks5"
    
    if not outbound:
        return False, link

    success = False
    
    # CASE A: Direct proxy check (HTTP or SOCKS5)
    if is_direct_check:
        curl_proxy = link
        if proxy_type == "socks5":
            # For socks5 we use socks5h:// to resolve DNS through proxy
            curl_proxy = link.replace("socks5://", "socks5h://")
            
        chk_cmd = [
            "curl", "-s", "--connect-timeout", "5", "--max-time", "10",
            "-x", curl_proxy,
            CHECK_URL
        ]
        try:
            result = subprocess.run(chk_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and len(result.stdout) > 6:
                success = True
        except Exception:
            success = False
        return success, link

    # CASE B: Xray-based proxy
    # 2. Write Config
    config = generate_config(outbound, local_port)
    with open(config_file, 'w') as f:
        json.dump(config, f)
        
    # 3. Start Xray
    try:
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.5)
        
        if proc.poll() is not None:
            success = False
        else:
            # 4. Curl check via socks
            chk_cmd = [
                "curl", "-s", "--connect-timeout", "5", "--max-time", "8",
                "-x", f"socks5h://127.0.0.1:{local_port}",
                CHECK_URL
            ]
            try:
                result = subprocess.run(chk_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode == 0 and len(result.stdout) > 6:
                    success = True
            except Exception:
                success = False
            
    except Exception as e:
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
            try: os.remove(config_file)
            except: pass
            
    return success, link


def fetch_proxies():
    print("Fetching new proxies from sources...")
    links = set()
    
    # Valid V2Ray/SS sources
    v2ray_urls = [
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vm.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/tr.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/ss.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
    ]
    
    # Plain HTTP sources (treated as HTTP)
    plain_http_urls = [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
    ]
    
    # Plain SOCKS5 sources (treated as SOCKS5)
    plain_socks5_urls = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"
    ]
    
    for url in v2ray_urls:
        print(f"Fetching V2Ray/SS: {url}")
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                if "vless://" not in content and "vmess://" not in content and "trojan://" not in content and "ss://" not in content:
                     try:
                         decoded = base64.b64decode(content).decode('utf-8')
                         content = decoded
                     except: pass
                
                for line in content.splitlines():
                    line = line.strip()
                    if line and (
                        line.startswith("vless://") or
                        line.startswith("vmess://") or
                        line.startswith("trojan://") or
                        line.startswith("ss://") or
                        line.startswith("http://") or
                        line.startswith("https://") or
                        line.startswith("socks5://")
                    ):
                        links.add(line)
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")

    for url in plain_http_urls:
        print(f"Fetching Plain HTTP: {url}")
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line: continue
                    if re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', line):
                        links.add("http://" + line)
                    elif line.startswith("http"):
                        links.add(line)
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")

    for url in plain_socks5_urls:
        print(f"Fetching Plain SOCKS5: {url}")
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line: continue
                    if re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', line):
                        links.add("socks5://" + line)
                    elif line.startswith("socks5"):
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
                        l.startswith("ss://") or
                        l.startswith("http://") or
                        l.startswith("https://") or
                        l.startswith("socks5://")
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
            
    finally:
        for f in files.values():
            f.close()
            
    print(f"Distributed {len(unique_new_proxies)} UNIQUE proxies into {TOTAL_OUTPUT_LISTS} files in 'proxy_lists/'")

def save_general(proxies):
    # Save all found proxies to a single general list
    if not proxies: return

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
    
    # Check for recheck mode
    recheck_mode = "--recheck" in sys.argv
    if recheck_mode:
        print("!!! RECHECK MODE ENABLED !!!")
        print("Will re-verify ALL existing proxies and invalid ones will be removed.")

    if not shutil.which(XRAY_BIN) and not os.path.exists(XRAY_BIN):
        pass

    # 1. Load Proxies (Queue + Fetch)
    queue_links = load_queue()
    fetched_links = fetch_proxies()
    
    # Combine
    all_links = list(set(queue_links + fetched_links))
    
    # ----------------------------------------------------
    # LOAD EXISTING PROXIES
    # ----------------------------------------------------
    existing_proxies = set()
    
    if os.path.exists(RESULTS_FILE):
        try:
             with open(RESULTS_FILE, 'r') as f:
                 for line in f: existing_proxies.add(line.strip())
        except: pass

    for i in range(1, 21):
        fname = f"proxy_lists/list_{i}.txt"
        if os.path.exists(fname):
            try:
                with open(fname, 'r') as f:
                    for line in f: existing_proxies.add(line.strip())
            except: pass

    # ----------------------------------------------------
    # DEDUPLICATION vs RECHECK LOGIC
    # ----------------------------------------------------
    if recheck_mode:
        print(f"Loaded {len(existing_proxies)} existing proxies for re-verification.")
        # In recheck mode, we ADD existing proxies to the check list
        all_links.extend(list(existing_proxies))
        # Remove duplicates within the list itself
        all_links = list(set(all_links))
        
        # CLEAR OLD FILES so we can overwrite only with working ones
        print("Clearing old result files...")
        if os.path.exists(RESULTS_FILE):
            try: os.remove(RESULTS_FILE)
            except: pass
        
        if os.path.exists("proxy_lists"):
            try: shutil.rmtree("proxy_lists")
            except: pass
        os.makedirs("proxy_lists", exist_ok=True)
        
    else:
        # Normal mode: Skip proxies that are already known
        print("Loading existing proxies to skip duplicates...")
        # existing_proxies set is already populated above
            
        original_count = len(all_links)
        all_links = [l for l in all_links if l not in existing_proxies]
        print(f"Deduplication: Removed {original_count - len(all_links)} proxies already in lists. Remaining: {len(all_links)}")

    # Shuffle
    random.shuffle(all_links)
    
    print(f"Total proxies to check: {len(all_links)}")
    if len(all_links) == 0:
        print("No NEW proxies to check (all found are duplicates).")
        return

    working_proxies = []
    checked_proxies_set = set() # Track what we've touched to avoid double-checking
    checked_count = 0
    remaining_links = []
    
    # PASS 1: Check New/Queue Proxies
    print("\n=== STARTING PASS 1: CHECKING NEW PROXIES ===")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_link = {}
        link_iterator = iter(all_links)
        exhausted = False
        
        while len(working_proxies) < TARGET_WORKING_COUNT and not exhausted:
            # Check Time Limit
            if time.time() - start_time > MAX_RUNTIME:
                print(f"Time limit reached ({MAX_RUNTIME}s). Stopping early.")
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
                
            try:
                for future in as_completed(future_to_link.keys(), timeout=1):
                    result_success, result_link = future.result()
                    checked_count += 1
                    checked_proxies_set.add(result_link)
                    
                    if result_success:
                        working_proxies.append(result_link)
                        print(f"[{len(working_proxies)}/{TARGET_WORKING_COUNT}] FOUND: {result_link[:30]}...")
                    
                    del future_to_link[future]
                    
                    if len(working_proxies) >= TARGET_WORKING_COUNT:
                        break
                    if time.time() - start_time > MAX_RUNTIME:
                        break
            except Exception:
                pass

            if len(working_proxies) >= TARGET_WORKING_COUNT:
                print("Target working count reached.")
                break
            
        remaining_links = list(future_to_link.values()) + list(link_iterator)

    # Save Results from Pass 1 (Append)
    if working_proxies:
        save_distributed(working_proxies)
        save_general(working_proxies)

    # Save Queue State (Everything we DID NOT check)
    # This includes:
    # 1. Links still in the future_to_link pool (didn't finish)
    # 2. Links still in the iterator (never started)
    all_remaining = list(future_to_link.values()) + list(link_iterator)
    if all_remaining:
        save_queue(all_remaining)
    else:
        # If queue is empty, remove file
        if os.path.exists(QUEUE_FILE):
            try: os.remove(QUEUE_FILE)
            except: pass
        print("Queue fully processed and cleared.")


    # ----------------------------------------------------
    # PASS 2: OPPORTUNISTIC RECHECK (If time remains)
    # ----------------------------------------------------
    elapsed = time.time() - start_time
    buffer_time = 300 # 5 minutes
    
    # Only run if we have time AND we aren't already in full recheck mode (which does this anyway)
    if not recheck_mode and (elapsed < (MAX_RUNTIME - buffer_time)):
        remaining_time = MAX_RUNTIME - elapsed
        print(f"\n=== TIME REMAINS ({int(remaining_time)}s) ===")
        print("Starting Opportunistic Recheck of existing list...")
        
        # 1. Load all existing proxies again
        recheck_candidates = set()
        if os.path.exists(RESULTS_FILE):
            try:
                 with open(RESULTS_FILE, 'r') as f:
                     for line in f: recheck_candidates.add(line.strip())
            except: pass
            
        for i in range(1, 21):
            fname = f"proxy_lists/list_{i}.txt"
            if os.path.exists(fname):
                try:
                    with open(fname, 'r') as f:
                        for line in f: recheck_candidates.add(line.strip())
                except: pass
        
        # 2. Filter out what we ALREADY checked in Pass 1
        # (This includes newly found ones that are now in the file, and ones we tried and failed)
        to_recheck = [p for p in recheck_candidates if p not in checked_proxies_set]
        random.shuffle(to_recheck)
        
        print(f"Found {len(recheck_candidates)} total existing. Rechecking {len(to_recheck)} (skipping {len(checked_proxies_set)} recently checked).")
        
        if to_recheck:
            verified_existing = []
            
            # We need to preserve the NEW working proxies we just found in Pass 1
            # But we will overwrite the files, so we start with them.
            final_good_proxies = list(working_proxies) 
            
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                future_to_link = {}
                link_iterator = iter(to_recheck)
                exhausted = False
                
                while True:
                    if time.time() - start_time > MAX_RUNTIME:
                        print("Time limit reached during recheck. Stopping.")
                        break
                        
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
                        
                    try:
                        for future in as_completed(future_to_link.keys(), timeout=1):
                            result_success, result_link = future.result()
                            checked_proxies_set.add(result_link)
                            
                            if result_success:
                                verified_existing.append(result_link)
                                final_good_proxies.append(result_link)
                                # Optional: Print less frequently for recheck
                                # print(f"  [Recheck] Verified: {result_link[:20]}...")
                            
                            del future_to_link[future]
                            
                            if time.time() - start_time > MAX_RUNTIME:
                                break
                    except: pass
            
            # 3. SAVE OVERWRITE
            # We have 'final_good_proxies' which contains:
            #  - Working proxies from Pass 1 (New)
            #  - Working proxies from Pass 2 (Old/Rechecked)
            # IMPORTANT: We did NOT recheck proxies in 'checked_proxies_set' that were in the file but skipped?
            # Wait, if we skipped them in Pass 2, it means we checked them in Pass 1. 
            # If they were in Pass 1 and failed, they are NOT in 'working_proxies'.
            # If they were in Pass 1 and succeeded, they ARE in 'working_proxies'.
            # So 'final_good_proxies' covers everything we touched.
            # BUT: What about proxies in file that we didn't touch because we ran out of time in Pass 2?
            # IF we run out of time, we shouldn't delete the unchecked ones!
            
            if exhausted and not future_to_link:
                # We finished checking EVERYTHING. We can safely overwrite.
                print(f"Recheck COMPLETE. Overwriting files with {len(final_good_proxies)} valid proxies.")
                
                # Clear files
                if os.path.exists(RESULTS_FILE): os.remove(RESULTS_FILE)
                if os.path.exists("proxy_lists"): shutil.rmtree("proxy_lists")
                
                save_distributed(final_good_proxies)
                save_general(final_good_proxies)
            else:
                # We ran out of time mid-recheck. We cannot overwrite safely because we'd lose unchecked proxies.
                # Instead, we should just append the confirmed rechecked ones (duplicates might happen?)
                # Or better: Just don't overwrite if not complete. 
                # Ideally, we'd like to remove the specifically FAILED ones.
                # But simple append is safer than data loss.
                print("Recheck interrupted (Time Limit). NOT overwriting files to prevent data loss of unchecked proxies.")
                print(f"Found {len(verified_existing)} valid existing proxies in this partial run.")
                # We don't save 'verified_existing' because they are already in the file.
                pass

    print(f"\nDone. Checked total: {len(checked_proxies_set)}")

if __name__ == "__main__":
    main()
