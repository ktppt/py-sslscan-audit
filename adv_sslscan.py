#!/usr/bin/env python3
import ssl
import socket
import argparse
import sys
import threading
import warnings
from queue import Queue

# --- COLORS & CONFIG ---
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'      
    GREEN = '\033[92m'    
    YELLOW = '\033[93m'   
    BLUE = '\033[94m'     
    PURPLE = '\033[95m'   
    CYAN = '\033[96m'
    GREY = '\033[90m'     
    BG_RED = '\033[41m'

warnings.simplefilter('ignore', DeprecationWarning)

# --- RISK ANALYSIS LOGIC ---
def analyze_cipher_strength(protocol, cipher_name):
    # 1. Critical Keywords
    critical_keywords = ['NULL', 'EXP', 'ADH', 'AECDH', 'RC4', 'MD5', 'DES'] 
    for kw in critical_keywords:
        if kw in cipher_name:
            return Colors.RED, "CRITICAL"

    # 2. Old Protocols
    if protocol in ['SSLv2', 'SSLv3']:
        return Colors.RED, "CRITICAL (Old Proto)"
    
    # 3. Weak/Medium Logic
    if '3DES' in cipher_name:
        return Colors.RED, "WEAK (3DES)"
    
    # Logic: AES-CBC vs GCM
    is_gcm = 'GCM' in cipher_name
    is_poly = 'POLY1305' in cipher_name
    is_ccm = 'CCM' in cipher_name
    
    if not (is_gcm or is_poly or is_ccm):
        return Colors.YELLOW, "WEAK (CBC/Legacy)"

    if protocol in ['TLSv1.0', 'TLSv1.1']:
        return Colors.YELLOW, "MEDIUM (Old Proto)"

    return Colors.GREEN, "STRONG"

# --- HELPER: Connectivity ---
def check_connectivity(target, port):
    print(f"{Colors.BLUE}[*] Checking connectivity to {target}:{port}...{Colors.RESET}")
    try:
        ip = socket.gethostbyname(target)
        sock = socket.create_connection((target, port), timeout=5)
        sock.close()
        return True
    except Exception as e:
        print(f"{Colors.RED}[!] FATAL: Cannot connect. {e}{Colors.RESET}")
        return False

# --- HELPER: Special Checks (ALPN, Compression, Preference) ---
def get_server_preference(target, port, protocol_version):
    """ หา Cipher ที่ Server เลือกเป็นอันดับแรก (Preferred) """
    try:
        context = ssl.SSLContext(protocol_version)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try: context.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
        except: pass
        
        with socket.create_connection((target, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                return ssock.cipher()[0]
    except:
        return None

def check_alpn(target, port):
    """ ตรวจสอบ HTTP/2 Support """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['h2', 'http/1.1'])
        
        with socket.create_connection((target, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                return ssock.selected_alpn_protocol()
    except:
        return None

def check_compression(target, port):
    """ ตรวจสอบ TLS Compression (CRIME Risk) """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Python SSL default disables compression, hard to force enable via high-level API
        # But we can check result
        with socket.create_connection((target, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                comp = ssock.compression()
                return comp if comp else "None"
    except:
        return "Unknown"

# --- WORKER ---
def test_cipher(target, port, cipher_str, protocol_version, result_queue):
    try:
        context = ssl.SSLContext(protocol_version)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Force Kali/OpenSSL 3
        try: context.set_ciphers(f"{cipher_str}:@SECLEVEL=0")
        except: 
            try: context.set_ciphers(cipher_str)
            except: return

        try: context.options |= ssl.OP_LEGACY_SERVER_CONNECT
        except: pass
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            ssock.connect((target, port))
            c = ssock.cipher()
            result_queue.put({
                'protocol': ssock.version(),
                'cipher': c[0],
                'bits': c[2],
                'curve': '' # Python ssl doesn't expose curve name easily in cipher() tuple
            })
    except:
        pass

# --- MAIN ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target Host")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("-t", "--threads", type=int, default=30)
    args = parser.parse_args()

    target = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    
    if not check_connectivity(target, args.port):
        sys.exit(1)

    # 1. SPECIAL FEATURES SUMMARY
    print(f"\n{Colors.PURPLE}=== Service Features ==={Colors.RESET}")
    
    # ALPN Check
    alpn = check_alpn(target, args.port)
    alpn_str = f"{Colors.GREEN}Enabled ({alpn}){Colors.RESET}" if alpn else f"{Colors.GREY}Disabled/Not Supported{Colors.RESET}"
    print(f"  HTTP/2 Support (ALPN) : {alpn_str}")

    # Compression Check
    comp = check_compression(target, args.port)
    comp_str = f"{Colors.RED}Enabled ({comp}) [CRIME Risk]{Colors.RESET}" if comp != "None" else f"{Colors.GREEN}Disabled{Colors.RESET}"
    print(f"  TLS Compression       : {comp_str}")

    # 2. PROTOCOLS & PREFERENCES
    print(f"\n{Colors.PURPLE}=== Protocols & Preference ==={Colors.RESET}")
    protocols_map = [
        ('SSLv2', None), 
        ('SSLv3', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
        ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
        ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
        ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
        ('TLSv1.3', ssl.PROTOCOL_TLS_CLIENT),
    ]
    
    active_protos = []
    preferred_ciphers = {} # Map protocol -> preferred cipher name
    
    for p_name, p_const in protocols_map:
        if p_const:
            pref = get_server_preference(target, args.port, p_const)
            if pref:
                print(f"  {p_name:<10} : {Colors.GREEN}Enabled{Colors.RESET}  (Preferred: {Colors.CYAN}{pref}{Colors.RESET})")
                active_protos.append((p_name, p_const))
                preferred_ciphers[p_name] = pref
            else:
                print(f"  {p_name:<10} : {Colors.RED}Disabled{Colors.RESET}")
        else:
             print(f"  {p_name:<10} : {Colors.GREY}Not Supported by Client{Colors.RESET}")

    # 3. CIPHER ENUMERATION
    print(f"\n{Colors.PURPLE}=== Cipher Suites ==={Colors.RESET}")
    
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try: ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except: pass
    local_ciphers = ctx.get_ciphers()
    
    cipher_names = set(c['name'] for c in local_ciphers)
    manual_weak = ['RC4-MD5', 'RC4-SHA', 'DES-CBC3-SHA', 'AES128-SHA', 'AES256-SHA', 'NULL-MD5', 'NULL-SHA']
    for w in manual_weak: cipher_names.add(w)
        
    q = Queue()
    results = []
    
    def worker():
        while True:
            task = q.get()
            if task is None: break
            c_name, p_const = task
            res_q = Queue()
            test_cipher(target, args.port, c_name, p_const, res_q)
            if not res_q.empty():
                results.append(res_q.get())
            q.task_done()

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for p_name, p_const in active_protos:
        for c_name in cipher_names:
            q.put((c_name, p_const))
            
    q.join()
    for _ in range(args.threads): q.put(None)
    for t in threads: t.join()

    # Sort and Display
    unique_results = {}
    for r in results:
        key = f"{r['protocol']}-{r['cipher']}"
        if key not in unique_results: unique_results[key] = r
    sorted_res = sorted(unique_results.values(), key=lambda x: (x['protocol'], x['cipher']))

    print("-" * 100)
    print(f"{'Protocol':<10} | {'Cipher Suite':<50} | {'Bits':<5} | {'Status'}")
    print("-" * 100)

    last_proto = ""
    for res in sorted_res:
        if res['protocol'] != last_proto and last_proto != "": print("-" * 100)
        last_proto = res['protocol']
        
        color, risk_text = analyze_cipher_strength(res['protocol'], res['cipher'])
        
        # Check Preference
        is_preferred = False
        if res['protocol'] in preferred_ciphers:
             # Note: TLS 1.3 protocols might negotiate differently (TLS_AES...), simple string match usually works
             if preferred_ciphers[res['protocol']] == res['cipher']:
                 is_preferred = True

        pref_tag = f" {Colors.CYAN}(Preferred){Colors.RESET}" if is_preferred else ""
        
        print(f"{res['protocol']:<10} | {color}{res['cipher']:<50}{Colors.RESET} | {res['bits']:<5} | {color}{risk_text}{Colors.RESET}{pref_tag}")

    print("-" * 100)

    # 4. CERTIFICATE DETAILS (Expanded)
    print(f"\n{Colors.PURPLE}=== Certificate Information ==={Colors.RESET}")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((target, args.port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                
                # Basic
                sub = dict(x[0] for x in cert['subject'])
                iss = dict(x[0] for x in cert['issuer'])
                print(f"  Subject CN    : {Colors.GREEN}{sub.get('commonName')}{Colors.RESET}")
                print(f"  Issuer CN     : {Colors.GREEN}{iss.get('commonName')}{Colors.RESET}")
                print(f"  Not After     : {Colors.YELLOW}{cert.get('notAfter')}{Colors.RESET}")
                print(f"  Serial Number : {cert.get('serialNumber')}")
                
                # SANs (Subject Alternative Names)
                sans = cert.get('subjectAltName', [])
                if sans:
                    print(f"  Subject Alt Names:")
                    for typ, val in sans:
                        print(f"    - {typ}: {val}")

    except Exception as e:
        print(f"  {Colors.RED}Could not retrieve full cert info: {e}{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Cancelled.")
