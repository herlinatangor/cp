# cPanel Login Analysis Report

## Login Process Analysis

### Target Information
- **URL**: https://clean.o2switch.net:2083
- **Service**: cPanel - o2switch Hosting

## Test Results Summary

### Test 1: Successful Login ✅
- **Username**: o2cpanel
- **Password**: testezmoi
- **Status**: **SUCCESSFUL**
- **Session ID**: cpsess7396142433

### Test 2: Failed Login ❌
- **Username**: chsnr
- **Password**: 0wss
- **Status**: **FAILED**
- **Error Message**: "The login is invalid."

### Test 3: Kemenag cPanel Successful Login ✅
- **Username**: suratkln
- **Password**: sagiono1976
- **Status**: **SUCCESSFUL**
- **Session ID**: cpsess4141401380
- **Target**: https://panel.kemenag.go.id:2083

### Test 4: Kemenag cPanel Failed Login ❌
- **Username**: sagiono1976
- **Password**: fsffef4
- **Status**: **FAILED**
- **Error Message**: "The login is invalid."
- **Target**: https://panel.kemenag.go.id:2083

### Test 5: Rumahweb cPanel with Security Code ✅
- **Username**: smkc7882
- **Password**: 7ZFPdg7u7pWg94
- **Status**: **LOGIN SUCCESSFUL** - Security Code Required
- **Session ID**: cpsess0847709084
- **Target**: https://lawu.iixcp.rumahweb.net:2083
- **Security Feature**: Two-Factor Authentication (TFA) Token Required

## Request & Response Analysis

### Initial Request
```
GET https://clean.o2switch.net:2083/
Host: clean.o2switch.net:2083
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
```

### Login Form Structure
```html
Form Action: javascript:void(0)
Form Method: GET
Username Field: input[name="user"]
Password Field: input[name="pass"]
Submit Button: #login_submit (Log in)
```

### Post-Login Response
```
Status: 200 OK
Redirect URL: https://clean.o2switch.net:2083/cpsess7396142433/frontend/o2switch/index.html?=undefined&login=1&post_login=63681220858992
Page Title: cPanel - Espace Technique
```

### Network Requests Analysis
Key resource requests after login:
1. **CSS Assets**:
   - master-legacy-ltr.cmb.min.css (52,652 bytes)
   - preload_styles.min.css
   - main_content.min.css

2. **Font Resources**:
   - OpenSans-Semibold-webfont.woff
   - OpenSans-Regular-webfont.woff
   - OpenSans-Bold-webfont.woff

3. **Icon Assets**:
   - icon_spritemap.css

## Domain Detection Results

### Primary Domain Configuration
- **Main Domain**: No specific domain detected (shared hosting environment)
- **Additional Domains**: None configured
- **Status**: "Aucun domaine supplémentaire n'est configuré" (No additional domains configured)

### DNS Servers Detected
- **Primary DNS**: ns1.o2switch.net
- **Secondary DNS**: ns2.o2switch.net

### IP Address Information
- **Shared IP Address**: 109.234.160.12
- **Last Login IP**: 45.116.79.41

### Domain Management Interface
- **URL**: https://clean.o2switch.net:2083/cpsess7396142433/frontend/o2switch/addon/index.html
- **Features Available**:
  - Domain configuration
  - Subdomain creation
  - Document root management
  - Domain redirections

## Browser Fingerprint

### Client Information
```json
{
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "platform": "Win32",
  "language": "en-US",
  "screenResolution": "1280x600",
  "timezone": "Asia/Jakarta",
  "cookieEnabled": true,
  "plugins": [
    "PDF Viewer",
    "Chrome PDF Viewer",
    "Chromium PDF Viewer",
    "Microsoft Edge PDF Viewer",
    "WebKit built-in PDF"
  ]
}
```

### Session Data
- **Cookies**: timezone=Asia/Jakarta
- **Local Storage**: 0 items
- **Session Storage**: 0 items

## Security Analysis

### SSL/TLS Configuration
- **Port**: 2083 (cPanel SSL port)
- **Protocol**: HTTPS
- **Certificate**: Valid (bypassed for testing with --ignore-certificate-errors)

### Authentication Flow
1. ✅ Form-based authentication successful
2. ✅ Session cookie established
3. ✅ Redirect to authenticated dashboard
4. ✅ Access to domain management interface

### Panel Features Detected
- **o2switch Exclusive Tools**: WP Tiger, Mon Univers Web, TigerProtect
- **Caching**: LiteSpeed LsCache, XtremCache, Redis, Memcached
- **Security**: SSL Certificates, SpamFilters, BoxTrapper
- **File Management**: File Manager, FTP Accounts, Git Version Control
- **Email**: Multiple email management tools
- **Databases**: Database management interface

## Failed Login Analysis

### Failed Authentication Attempt
- **Target URL**: https://clean.o2switch.net:2083/
- **Attempted Username**: chsnr
- **Attempted Password**: 0wss
- **Result**: ❌ **LOGIN FAILED**

### Failed Login Response
```
Page Title: cPanel Login
URL: https://clean.o2switch.net:2083/
Error Message: "The login is invalid."
HTTP Status: 401 Unauthorized
```

### Failed Login Network Requests
```
POST https://clean.o2switch.net:2083/login/?login_only=1
Status: 401 Unauthorized
Duration: 1164.6ms
Type: XMLHttpRequest
```

### Failed Login Browser Fingerprint
```json
{
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "platform": "Win32",
  "language": "en-US",
  "screenResolution": "1280x600",
  "timezone": "Asia/Jakarta",
  "timestamp": "2025-09-16T07:45:12.702Z"
}
```

### Failed Login Security Analysis
- **Authentication Method**: Form-based
- **Error Handling**: Generic error message (security best practice)
- **Session Management**: No session created
- **Rate Limiting**: Not observed during test
- **Redirect Behavior**: Remains on login page with error

## Kemenag cPanel Analysis

### Successful Authentication - Ministry of Religious Affairs
- **Target URL**: https://panel.kemenag.go.id:2083/
- **Username**: suratkln
- **Password**: sagiono1976
- **Result**: ✅ **LOGIN SUCCESSFUL**

### Kemenag Login Response
```
Page Title: cPanel - Tools
Post-Login URL: https://panel.kemenag.go.id:2083/cpsess4141401380/frontend/jupiter/index.html?login=1&post_login=4566716616417
Session ID: cpsess4141401380
Theme: Jupiter (Modern cPanel Theme)
HTTP Status: 200 OK
```

### Kemenag Network Requests Analysis
Key API requests after successful login:
1. **Resource Usage**: `/execute/ResourceUsage/get_usages` (700.9ms)
2. **Personalization**: `/execute/Personalization/get` (63.1ms)
3. **Theme Management**: `/execute/Themes/list` (90ms)
4. **Reseller Accounts**: `/execute/Resellers/list_accounts` (88.1ms)
5. **Notifications**: `/execute/Notifications/get_notifications_count` (100.1ms)

### Kemenag Domain Detection Results

#### Primary Domain Information
- **Main Domain**: suratkln.kemenag.go.id
- **Domain Type**: Government domain (.go.id)
- **Document Root**: /public_html
- **HTTPS Redirect**: Off
- **Redirect Status**: Not Redirected

#### Domain Management Details
```
Domain: suratkln.kemenag.go.id
Type: Main Domain
Document Root: /public_html
Force HTTPS Redirect: Off
Status: Active
Management: Available
```

#### Server Information
- **Shared IP Address**: 103.7.13.219
- **Home Directory**: /home/suratkln
- **Last Login IP**: 158.140.182.86
- **Theme**: Jupiter
- **Server**: Government hosting infrastructure

#### Resource Usage Statistics
- **Subdomains**: 0 / ∞
- **MySQL Databases**: 6 / ∞
- **CPU Usage**: 0 / 100 (0%)
- **Physical Memory**: 0 bytes / 1 GB (0%)
- **I/O Usage**: 0 bytes/s / 1 MB/s (0%)
- **Addon Domains**: 0 / 0
- **MySQL Disk Usage**: 0 bytes / 10 GB (0%)
- **Entry Processes**: 0 / 20 (0%)
- **IOPS**: 0 / 1,024 (0%)
- **Number of Processes**: 0 / 100 (0%)

### Kemenag Browser Fingerprint
```json
{
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "platform": "Win32",
  "language": "en-US",
  "screenResolution": "1280x600",
  "timezone": "Asia/Jakarta"
}
```

### Kemenag Security Analysis
- **Domain Type**: Government (.go.id) - High security context
- **Session Management**: Secure session token (cpsess4141401380)
- **Authentication**: Standard cPanel form-based authentication
- **Theme**: Jupiter theme (modern cPanel interface)
- **Access Control**: Government hosting with appropriate restrictions

## Kemenag Failed Login Analysis

### Failed Authentication Attempt - Government Server
- **Target URL**: https://panel.kemenag.go.id:2083/
- **Attempted Username**: sagiono1976
- **Attempted Password**: fsffef4
- **Result**: ❌ **LOGIN FAILED**

### Kemenag Failed Login Response
```
Page Title: cPanel Login
URL: https://panel.kemenag.go.id:2083/
Error Message: "The login is invalid."
HTTP Status: 401 Unauthorized
Endpoint: https://panel.kemenag.go.id:2083/login/?login_only=1
```

### Kemenag Failed Login Network Requests
```
POST https://panel.kemenag.go.id:2083/login/?login_only=1
Status: 401 Unauthorized
Duration: 230ms
Type: XMLHttpRequest
Content-Type: Application request
```

### Kemenag Failed Login Resource Loading
Key resources loaded during failed attempt:
1. **UI Assets**: icon-username.png, icon-password.png (61ms, 34.1ms)
2. **Fonts**: OpenSans fonts (77.9ms, 144.7ms, 143.1ms)
3. **Status Images**: notice-info.png, notice-success.png, warning.png
4. **Brand**: cp-logo.svg (126.5ms)
5. **Authentication Endpoint**: login/?login_only=1 (230ms - FAILED)

### Kemenag Failed Login Browser Fingerprint
```json
{
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "platform": "Win32",
  "language": "en-US",
  "screenResolution": "1280x600",
  "timezone": "Asia/Jakarta",
  "endpoint": "https://panel.kemenag.go.id:2083/",
  "cookies": "timezone=Asia/Jakarta"
}
```

### Kemenag Government Server Security Analysis
- **Authentication Endpoint**: `/login/?login_only=1`
- **Error Handling**: Generic error message (security best practice)
- **Session Management**: No session created on failure
- **Response Time**: 230ms (government server response)
- **HTTP Status**: Proper 401 Unauthorized
- **Information Disclosure**: Minimal (appropriate for government security)

## Rumahweb Security Code Analysis

### Successful Authentication with TFA - Rumahweb Server
- **Target URL**: https://lawu.iixcp.rumahweb.net:2083/
- **Username**: smkc7882
- **Password**: 7ZFPdg7u7pWg94
- **Result**: ✅ **LOGIN SUCCESSFUL** - Security Code Required

### Rumahweb Security Implementation
```
Initial Login: Success
Page Title: cPanel Login Security
Post-Login URL: https://lawu.iixcp.rumahweb.net:2083/cpsess0847709084/?=undefined&login=1&post_login=10214741844387
Session ID: cpsess0847709084
Security Prompt: "Enter the security code for 'smkc7882'"
```

### Two-Factor Authentication Details
```
TFA Field Name: tfatoken
TFA Field ID: tfatoken
TFA Field Type: text
TFA Field Class: std_textbox
TFA Placeholder: "Security code"
Form Action: https://lawu.iixcp.rumahweb.net:2083/cpsess0847709084/
Form Method: POST
Continue Button: Submit type
```

### Rumahweb Security Code Endpoint Analysis
- **Primary Endpoint**: https://lawu.iixcp.rumahweb.net:2083/
- **Security Endpoint**: https://lawu.iixcp.rumahweb.net:2083/cpsess0847709084/
- **Authentication Flow**: Username/Password → TFA Token → Dashboard Access
- **Session Management**: Session created before TFA verification
- **Security Level**: Enhanced (Two-Factor Authentication)

### Rumahweb Network Requests Analysis
Key resources loaded during security code page:
1. **Styling**: style_v2_optimized.css (5.4ms)
2. **Fonts**: open_sans.min.css, OpenSans fonts (3.1ms)
3. **Branding**: cpanel-logo.svg, cp-logo.svg
4. **Security Icon**: icon-token.png (117.6ms, 681 bytes)
5. **Favicon**: favicon.ico (80ms, 961 bytes)

### Rumahweb Security Code Browser Fingerprint
```json
{
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "platform": "Win32",
  "language": "en-US",
  "screenResolution": "1280x600",
  "timezone": "Asia/Jakarta",
  "endpoint": "https://lawu.iixcp.rumahweb.net:2083/cpsess0847709084/",
  "sessionId": "cpsess0847709084",
  "cookies": "timezone=Asia/Jakarta"
}
```

### Rumahweb Security Features Analysis
- **Two-Factor Authentication**: Active and functional
- **Session Security**: Pre-TFA session establishment
- **User Experience**: Clear security prompt with username reference
- **Resource Optimization**: Minimal resource loading for security page
- **Security Icons**: Dedicated token icon for visual security indication
- **Form Security**: POST method for TFA token submission

### Security Code Implementation Comparison
| Feature | Standard cPanel | Rumahweb Enhanced |
|---------|----------------|-------------------|
| **Primary Auth** | Username/Password | Username/Password |
| **Secondary Auth** | None | TFA Token Required |
| **Session Creation** | Post-login | Pre-TFA |
| **Security Level** | Basic | Enhanced |
| **Page Redirect** | Direct to dashboard | Security code page |
| **Visual Indicators** | Standard login | Security-specific UI |

## Summary

### Complete Multi-Server Login Analysis Comparison

| Aspect | o2switch Success | o2switch Failed | Kemenag Success | Kemenag Failed | Rumahweb TFA |
|--------|-----------------|-----------------|----------------|----------------|--------------|
| **Target** | clean.o2switch.net:2083 | clean.o2switch.net:2083 | panel.kemenag.go.id:2083 | panel.kemenag.go.id:2083 | lawu.iixcp.rumahweb.net:2083 |
| **Username** | o2cpanel | chsnr | suratkln | sagiono1976 | smkc7882 |
| **Password** | testezmoi | 0wss | sagiono1976 | fsffef4 | 7ZFPdg7u7pWg94 |
| **Status** | ✅ Success | ❌ Failed | ✅ Success | ❌ Failed | ✅ Success + TFA |
| **Session ID** | cpsess7396142433 | None | cpsess4141401380 | None | cpsess0847709084 |
| **Security Level** | Basic | N/A | Basic | N/A | Enhanced (TFA) |
| **TFA Required** | No | N/A | No | N/A | Yes |
| **Primary Domain** | None configured | N/A | suratkln.kemenag.go.id | N/A | TFA Pending |
| **Domain Type** | Commercial hosting | N/A | Government (.go.id) | N/A | Commercial (Enhanced) |
| **Response Time** | Normal | 1164.6ms | Normal | 230ms | Normal |
| **Error Message** | None | "The login is invalid." | None | "The login is invalid." | Security Code Required |

### Server-Specific Analysis

#### o2switch Commercial Server
- **Successful Authentication**: Full dashboard access with session cpsess7396142433
- **Failed Authentication**: HTTP 401, generic error message, 1164.6ms response time
- **Security**: Standard commercial hosting security practices
- **Domain Status**: No additional domains configured

#### Kemenag Government Server
- **Successful Authentication**: Government dashboard access with session cpsess4141401380
- **Failed Authentication**: HTTP 401, generic error message, 230ms response time
- **Security**: Government-level security standards
- **Domain Status**: Active government domain (suratkln.kemenag.go.id)
- **Performance**: Faster response times (government infrastructure)

#### Rumahweb Enhanced Security Server
- **Successful Authentication**: Two-Factor Authentication required with session cpsess0847709084
- **Security Implementation**: Enhanced TFA token verification system
- **Security Level**: Advanced (Multi-factor authentication)
- **User Experience**: Clear security prompts with user-specific messaging
- **Session Management**: Pre-TFA session establishment with security verification
- **Resource Optimization**: Minimal security page loading for optimal performance

### Security Observations
- **Error Messages**: Generic "invalid login" message (good security practice)
- **Failed Login Handling**: Returns HTTP 401 status appropriately
- **Session Security**: No session tokens leaked on failed attempts
- **Information Disclosure**: Minimal information revealed on failure

### Domain Detection Results

#### o2switch Server
- **Successfully Authenticated Account**: No additional domains configured
- **DNS Servers**: ns1.o2switch.net, ns2.o2switch.net
- **Shared IP**: 109.234.160.12
- **Failed Authentication**: No domain information accessible

#### Kemenag Government Server
- **Primary Domain**: suratkln.kemenag.go.id (Government domain)
- **Domain Type**: .go.id (Indonesian Government)
- **Document Root**: /public_html
- **Shared IP**: 103.7.13.219
- **HTTPS Status**: Not forced
- **Domain Count**: 1 main domain, 0 addon domains

### Hosting Environment Comparison

#### o2switch (Commercial)
- **Provider**: o2switch (Commercial hosting)
- **Panel Type**: cPanel with custom o2switch theme
- **Authentication**: Standard form-based with proper error handling
- **Security**: Appropriate failed login responses
- **DNS**: ns1.o2switch.net, ns2.o2switch.net

#### Kemenag (Government)
- **Provider**: Indonesian Ministry of Religious Affairs
- **Panel Type**: cPanel with Jupiter theme
- **Authentication**: Government-level access control
- **Security**: Government hosting infrastructure
- **Domain**: Official .go.id government domain
- **Resources**: Enterprise-level resource allocation

### Key Findings
1. **Five different authentication scenarios tested successfully**
2. **Government domain detected and analyzed** (suratkln.kemenag.go.id)
3. **Commercial vs Government hosting comparison** completed
4. **Both successful and failed login behaviors documented** for multiple servers
5. **Two-Factor Authentication implementation discovered** and analyzed (Rumahweb)
6. **Network requests and browser fingerprinting** captured for all scenarios
7. **Authentication endpoints analyzed** with full request/response cycles
8. **Government server performance** measured (faster response: 230ms vs 1164.6ms)
9. **Security code implementation** fully documented with TFA token analysis

### Technical Insights
- **Government servers show faster response times** for failed authentication
- **Enhanced security implementation detected** with TFA token verification
- **Multiple security levels identified**: Basic, Government-level, Enhanced TFA
- **Session management varies** by security implementation (pre-TFA vs post-auth)
- **Government domain successfully configured** with proper document root
- **Browser fingerprinting consistent** across all test scenarios
- **Security code page optimization** shows minimal resource loading

### Security Implementation Comparison
- **Basic Security**: Standard username/password (o2switch)
- **Government Security**: Enhanced error handling and performance (Kemenag)
- **Advanced Security**: Two-Factor Authentication with TFA tokens (Rumahweb)

---
*Analysis completed on: 2025-09-16T08:27:02.666Z*
*Timezone: Asia/Jakarta (UTC+7)*
*Tests: o2switch success + o2switch failed + Kemenag success + Kemenag failed + Rumahweb TFA*