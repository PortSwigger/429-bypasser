
# 429 Bypasser Burp Suite Extension

## Overview
The **429 Bypasser** is a Burp Suite extension designed to help penetration testers and security professionals bypass HTTP 429 (Too Many Requests) rate-limiting mechanisms. The extension employs various techniques to circumvent rate-limiting and provides a flexible interface for customizing bypass strategies.

## Features
- **Add Custom Headers**
- **Change User Agent**
- **Use Capital Letters**
- **Use Random Parameters**
- **Server-side HTTP Parameter Pollution**
- **Change HTTP Method**
- **Route Alteration**
- **Encoding**
- **Add Null Bytes, spaces and etc**

For encoding, null bytes, and parameter pollution, users can specify which parameter(s) to target. If no parameter is specified, the extension applies changes to all parameters by default.

## Installation
1. Download the extension from GitHub
2. Open Burp Suite and navigate to **Extensions**.
3. Click **Add** and load the `.py` file.
4. Verify that the extension is active under the **Extensions** tab.

## Usage
1. **Configuration**:
   - Right-click on the desired request. Choose **Extensions > 429 Bypasser > Send To 429 Bypasser** tab.
   - Select the methods you want to use for bypassing 429.
   - Specify parameters for encoding, null byte insertion, or parameter pollution if needed (By default, it applies changes to all parameters one by one).
   - Click on the OK button.

2. **Intercepting Traffic**:
   - In the 429 Bypasser tab added at the top of the page, you can see the requests this extension sends. You can also sort the sent requests based on the Status Code column so that you can easily find the desired request if this limitation is bypassed.

## Methods Explained
### Add Custom Headers
Insert custom headers into the request. For example:
```
X-Forwarded-For: 127.0.0.2
```

### Change User Agent
Set some specific user-agent strings to evade detection.

### Use Capital Letters
It randomly capitalizes some characters in the path and sends the request. For example:
```
Orginal: https://example.com/test/example
Changed: 
https://example.com/tEst/ExaMple
https://example.com/TEsT/exaMplT
https://example.com/teSt/eXAMpLe
...
```

### Use Random Parameters
Append random query parameters to requests to make them unique. Example:
```
https://example.com/resource?id=123&random=4895
```

### Server-side HTTP Parameter Pollution
Adds a duplicate parameter with different values.
```
Orginal: https://example.com/resource?username=admin
Changed:
https://example.com/resource?username=admin&username=admin2
https://example.com/resource?username=admin2&username=admin
```

### Change HTTP Method
Switch between methods like `GET`, `POST`, `PUT`, etc.

### Route Alteration
Modify URL paths, e.g.,
```
https://example.com/resource
```
becomes
```
https://example.com/resource/..
```
### Encoding
URL encoded some characters of parameter values
```
email=user@example.com
```
becomes
```
email=u%73%65r@example.com
```

### Add Null Bytes, spaces and etc
Inject (`%00`), (`%20`) and etc into parameter values:


## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch.
3. Commit your changes.
4. Submit a pull request.

## Contact
LinkedIn: <a href="https://ir.linkedin.com/in/iliya-afifi-bb11a2212" target="_blank">Click Here</a>

---
### Disclaimer
This tool is intended for legal penetration testing and research purposes only. The author is not responsible for any misuse.
