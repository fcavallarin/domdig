# DOMDig
DOMDig is a DOM XSS scanner that runs inside the Chromium web browser and it can scan single page applications (SPA) recursively.  
Unlike other scanners, DOMDig can crawl any webapplication (including gmail) by keeping track of DOM modifications and XHR/fetch/websocket requests and it can simulate a real user interaction by firing events. During this process, XSS payloads are put into input fields and their execution is tracked in order to find injection points and the related URL modifications.  
It is based on [htcrawl](https://htcrawl.org), a node library powerful enough to easily crawl a gmail account.


# KEY FEATURES
- Runs inside a real browser (Chromium)
- Recursive DOM crawling engine
- Handles XHR, fetch, JSONP and websockets requests
- Supports cookies, proxy, custom headers, http auth and more
- Scriptable login sequences
- Sequence recorder
- Postmessage fuzzer

# GETTING STARTED
## Installation
```
git clone https://github.com/fcavallarin/domdig.git
cd domdig && npm i && cd ..
node domdig/domdig.js
```

## Example
```
node domdig.js -c 'foo=bar' -p http:127.0.0.1:8080 https://fcvl.net/htcap/scanme/domxss.php
```

# PERFORMED CHECKS
DOMDig can perform three different checks:  
1. DOM XSS
2. Stored DOM XSS
3. Template Injection
4. postMessage XSS

## DOM XSS
DOM XSS check can be configured with different modes, enabling different behaviours. By default, all of them are enabled.  
The modes are:  
1. domscan
2. fuzz

### domscan
It crawls the DOM searching for places where user can inject JavaScript code, for example, a text box. It can discover injection points that cannot
be guessed by a scanner. An example may be a search functionality that takes the text of an input box and, to trigger the search, puts it into 
the URL's hash as a JSON string. 

### fuzz
It fuzzes the URL (query parameters and the hash) to see if our code gets executed on page load. If no code is executed, it crawls the
DOM triggering HTML events hoping to find something that executes our payload.  
It can also discover the classical Reflected XSS.

## Stored DOM XSS
After a DOM XSS check is performed, DOMDig crawls the same page waiting for the execution of previously used
payloads. If one is found, it means that is can survive to page reloads.

## Template Injection
Searches for places where template placeholders (e.g. `{var1}`) may be evaluated as JavaScript code.

# Reported Vulnerabilities
Every reported vulnerability contains the following fields:
1. **type**: the type of vulnerability, it can be `domxss`, `stored` or `templateinj`
2. **url**: the URL of the page when the vulnerability was found
3. **payload**: the payload used
4. **element**: the CSS selector of the HTML element, if any, where we injected our payload
5. **description**: a textual description
6. **confirmed**: a vulnerability is considered as confirmed when the URL contains the attack payload. If it's 
not confirmed, it means that the code has been successfully executed, but a manual analysis may be required 
to understand the relation between the injected payload and the URL schema.


# Crawl Engine
DOMDig uses [htcrawl](https://htcrawl.org) as crawling engine.  
The diagram shows the recursive crawling process.  
![SPA Crawling Diagram](https://htcrawl.org/img/htcap-flowchart.png).   
The video below shows the engine crawling gmail. The crawl lasted for many hours and about 3000 XHR request have been captured.

[![crawling gmail](https://fcvl.net/htcap/img/htcap-gmail-video.png)](https://www.youtube.com/watch?v=5FLmWjKE2JI "HTCAP Crawling Gmail")

# Login Sequence
A login sequence (or initial sequence) is a json object containing a list of actions to take before the scan starts.
Each element of the list is an array where the first element is the name of the action to take and the remaining elements are "parameters" to those actions.
Actions are:
- navigate &lt;url&gt;
- write &lt;selector&gt; &lt;text&gt;
- select &lt;selector&gt; &lt;value&gt;
- click &lt;selector&gt;
- clickToNavigate &lt;selector&gt;
- sleep &lt;seconds&gt;
- setTarget &lt;selector&gt;

## Example
```
[
   ["navigate", "https://target.local/login-page"],
   ["write", "#username", "demo"],
   ["write", "#password", "demo"],
   ["sleep", 2],
   ["clickToNavigate", "#btn-login"]
]
```

# Payloads file
Payloads can be loaded from json file (-P option) as array of strings. To build custom payloads, the string `window.___xssSink({0})` must be used as the function to be executed (instead of the classic `alert(1)`)

## Example
```
[
   ';window.___xssSink({0});',
   '<img src="a" onerror="window.___xssSink({0})">'
]
```
