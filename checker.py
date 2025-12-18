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
CHECK_URL = "http://www.google.com" # Or a lighter weight target
TIMEOUT = 6 # Seconds for curl/connect
MAX_THREADS = 200 # Faster scraping
BASE_PORT = 20000

# Staged Execution Config
TARGET_WORKING_COUNT = 1000 # Stop after finding this many working proxies
MAX_RUNTIME = 250 # Seconds (less than 5 mins) to ensure graceful exit and save
QUEUE_FILE = "proxies_queue.txt" # File to store unchecked proxies
RESULTS_FILE = "proxy_list_found.txt" # File to store working proxies (appended or overwritten)

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
    if link.startswith("vmess://"): outbound = parse_vmess(link)
    elif link.startswith("vless://"): outbound = parse_vless(link)
    elif link.startswith("trojan://"): outbound = parse_trojan(link)
    elif link.startswith("ss://"): outbound = parse_ss(link)
    
    if not outbound:
        return False, link

    # 2. Write Config
    config = generate_config(outbound, local_port)
    with open(config_file, 'w') as f:
        json.dump(config, f)
        
    # 3. Start Xray
    # We use a subprocess. Popen allows us to kill it later.
    try:
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # Give it a moment to start
        time.sleep(0.5)
        
        # Check if process is still running
        if proc.poll() is not None:
            # It died
            stderr = proc.stderr.read().decode('utf-8', errors='ignore')
            if thread_id == 0: # Print only first thread error to avoid spam
                print(f"[DEBUG] Xray died immediately. Stderr: {stderr[:200]}")
            success = False
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
                if result.returncode == 0 and len(result.stdout) > 100:
                    # Assuming google returns more than 100 bytes
                    success = True
                else:
                    success = False
                    # Debug curl failure occasionally
                    if thread_id == 0 and random.random() < 0.05:
                         print(f"[DEBUG] Curl failed. Return: {result.returncode}, Stdout len: {len(result.stdout)}")
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
    
    # CONFIGURATION
    US_PROXY_URL = "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/refs/heads/main/working/countries/United%20States.txt"
    
    urls = [US_PROXY_URL]
    
    for url in urls:
        print(f"Fetching {url}")
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                
                # Try base64 decode if it looks like a blob and doesn't contain protocol headers
                if "vmess://" not in content and "vless://" not in content and "trojan://" not in content and "ss://" not in content:
                    try:
                        decoded = base64.b64decode(content).decode('utf-8')
                        content = decoded
                    except:
                        pass
                
                # Extract lines
                for line in content.splitlines():
                    line = line.strip()
                    if line and (line.startswith("vmess://") or line.startswith("vless://") or 
                                 line.startswith("trojan://") or line.startswith("ss://")):
                        links.add(line)
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
            
    return list(links)

def load_queue():
    if os.path.exists(QUEUE_FILE):
        try:
            with open(QUEUE_FILE, 'r') as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
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
    # Distribute proxies into 20 files
    # We will append to existing files if they exist, or create new ones
    # But usually for a fresh run we might want to overwrite or just append
    # The requirement is "дописывал почереди" (append in turn)
    
    # Create directory if needed
    os.makedirs("proxy_lists", exist_ok=True)
    
    # Open handles for 20 files
    files = {}
    for i in range(1, 21):
        files[i] = open(f"proxy_lists/list_{i}.txt", "a") # append mode
        
    try:
        for idx, proxy in enumerate(proxies):
            file_idx = (idx % 20) + 1
            files[file_idx].write(proxy + "\n")
    finally:
        for f in files.values():
            f.close()
            
    print(f"Distributed {len(proxies)} proxies into 20 files in 'proxy_lists/'")

def main():
    start_time = time.time()
    
    if not shutil.which(XRAY_BIN) and not os.path.exists(XRAY_BIN):
        # On Github Actions or Linux, we might need to download xray if not present
        pass
        # print(f"Error: {XRAY_BIN} not found. Please install Xray-core.")
        # sys.exit(1)

    # 1. Load Proxies (Queue or Fetch)
    all_links = load_queue()
    if not all_links:
        all_links = fetch_proxies()
        # Shuffle for randomness if just fetched
        random.shuffle(all_links)
    
    print(f"Total proxies to check: {len(all_links)}")
    if len(all_links) == 0:
        print("No proxies to check.")
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
