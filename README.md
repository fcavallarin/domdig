## DOMDig
DOMDig is a DOM XSS scanner that runs inside the Chromium web browser and it can scan single page applications (SPA) recursively.  
Unlike other scanners, DOMDig can crawl any webapplication (including gmail) by keeping track of DOM modifications and XHR/fetch/websocket requests and it can simulate a real user interaction by firing events. During this process, XSS payloads are put into input fields and their execution is tracked in order to find injection points and the related URL modifications.  
It is based on [htcrawl](https://htcrawl.org), a node library powerful enough to easily crawl a gmail account.


## KEY FEATURES
- Runs inside a real browser (Chromium)
- Recursive DOM crawling engine
- Handles XHR, fetch, JSONP and websockets requests
- Supports cookies, proxy, custom headers, http auth and more
- Scriptable login sequences

## GETTING STARTED
### Installation
```
git clone https://github.com/fcavallarin/domdig.git
cd domdig && npm i && cd ..
node domdig/domdig.js
```

### Example
```
node domdig.js -c 'foo=bar' -p http:127.0.0.1:8080 https://htcap.org/scanme/domxss.php
```

### Crawl Engine
DOMDig uses [htcrawl](https://htcrawl.org) as crawling engine, the same engine used by [htcap](https://htcap.org).  
The diagram shows the recursive crawling proccess.  
![SPA Crawling Diagram](https://htcrawl.org/img/htcap-flowchart.png) . 
The video below shows the engine crawling gmail. The crawl lasted for many hours and about 3000 XHR request have been captured.

[![crawling gmail](https://htcap.org/img/htcap-gmail-video.png)](https://www.youtube.com/watch?v=5FLmWjKE2JI "HTCAP Crawling Gmail")

### Login Sequence
A login sequence (or initial sequence) is a json object containing a list of actions to take before the scan starts.
Each element of the list is an array where the first element is the name of the action to take and the remaining elements are "parameters" to those actions.
Actions are:
- write &lt;selector&gt; &lt;text&gt;
- click &lt;selector&gt;
- clickToNavigate &lt;selector&gt;
- sleep &lt;seconds&gt;

#### Example
```
[
   ["write", "#username", "demo"],
   ["write", "#password", "demo"],
   ["clickToNavigate", "#btn-login"]
]
```

### Payloads file
Payloads can be loaded from json file (-P option) as array of strings. To build custom payloads, the string `window.___xssSink({0})` must be used as the function to be executed (instead of the classic `alert(1)`)

#### Example
```
[
   ';window.___xssSink({0});',
   '<img src="a" onerror="window.___xssSink({0})">'
]
```
