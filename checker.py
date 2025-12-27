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
MAX_RUNTIME = 3400 # Seconds (approx 29 mins) to match 30m schedule
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
    # PHASE 1: MAINTENANCE (Re-verify existing list)
    # ----------------------------------------------------
    print(f"\n=== PHASE 1: RE-VERIFYING {len(existing_proxies)} EXISTING PROXIES ===")
    
    verified_existing = []
    checked_count = 0
    checked_proxies_set = set() # Track for final Pass 2 filtering

    # If in recheck_mode, we use ALL existing. 
    # If not, we still check them first to keep things clean.
    to_reverify = list(existing_proxies)
    random.shuffle(to_reverify)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_link = {}
        link_iterator = iter(to_reverify)
        exhausted = False
        
        while not exhausted:
            if time.time() - start_time > MAX_RUNTIME:
                print(f"Time limit reached ({MAX_RUNTIME}s) during maintenance. Stopping Pass 1.")
                break

            while len(future_to_link) < MAX_THREADS * 2:
                try:
                    link = next(link_iterator)
                    future = executor.submit(check_proxy, link, len(future_to_link) % MAX_THREADS)
                    future_to_link[future] = link
                except StopIteration:
                    exhausted = True
                    break
            
            if not future_to_link: break
                
            try:
                for future in as_completed(future_to_link.keys(), timeout=1):
                    result_success, result_link = future.result()
                    checked_count += 1
                    checked_proxies_set.add(result_link)
                    
                    if result_success:
                        verified_existing.append(result_link)
                    
                    del future_to_link[future]
                    if time.time() - start_time > MAX_RUNTIME: break
            except: pass

    # If we finished Phase 1 OR if we want to update the file with what we found so far
    print(f"Maintenance finished. Found {len(verified_existing)} valid out of {len(checked_proxies_set)} checked.")
    
    # Overwrite files with verified ones (if we checked ANY, we should probably update)
    if checked_proxies_set:
        print("Updating result files with verified proxies...")
        if os.path.exists(RESULTS_FILE): os.remove(RESULTS_FILE)
        if os.path.exists("proxy_lists"): shutil.rmtree("proxy_lists")
        os.makedirs("proxy_lists", exist_ok=True)
        
        save_distributed(verified_existing)
        save_general(verified_existing)

    # ----------------------------------------------------
    # PHASE 2: EXPANSION (Check new proxies from queue/sources)
    # ----------------------------------------------------
    elapsed = time.time() - start_time
    if elapsed > MAX_RUNTIME - 60: # Less than 1 min left
        print("\nNot enough time left for expansion. Exiting.")
        return

    # Filter out what we already checked in Phase 1
    new_to_check = [l for l in all_links if l not in checked_proxies_set]
    random.shuffle(new_to_check)
    
    print(f"\n=== PHASE 2: CHECKING {len(new_to_check)} NEW PROXIES (Target: {TARGET_WORKING_COUNT}) ===")
    
    new_working = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_link = {}
        link_iterator = iter(new_to_check)
        exhausted = False
        
        while len(new_working) + len(verified_existing) < TARGET_WORKING_COUNT and not exhausted:
            if time.time() - start_time > MAX_RUNTIME:
                print(f"Time limit reached ({MAX_RUNTIME}s). Stopping Pass 2.")
                break

            while len(future_to_link) < MAX_THREADS * 2:
                try:
                    link = next(link_iterator)
                    future = executor.submit(check_proxy, link, len(future_to_link) % MAX_THREADS)
                    future_to_link[future] = link
                except StopIteration:
                    exhausted = True
                    break
            
            if not future_to_link: break
                
            try:
                for future in as_completed(future_to_link.keys(), timeout=1):
                    result_success, result_link = future.result()
                    checked_count += 1
                    checked_proxies_set.add(result_link)
                    
                    if result_success:
                        new_working.append(result_link)
                        print(f"[{len(verified_existing) + len(new_working)}/{TARGET_WORKING_COUNT}] FOUND NEW: {result_link[:30]}...")
                    
                    del future_to_link[future]
                    if len(new_working) + len(verified_existing) >= TARGET_WORKING_COUNT: break
                    if time.time() - start_time > MAX_RUNTIME: break
            except: pass

    # Append new working ones
    if new_working:
        print(f"Expansion found {len(new_working)} new unique proxies.")
        save_distributed(new_working)
        save_general(new_working)

    # Save leftovers to queue
    all_not_touched = list(future_to_link.values()) + list(link_iterator)
    if all_not_touched:
        save_queue(all_not_touched)
    else:
        if os.path.exists(QUEUE_FILE): os.remove(QUEUE_FILE)

    print(f"\nDone. Checked total: {checked_count}")

if __name__ == "__main__":
    main()
