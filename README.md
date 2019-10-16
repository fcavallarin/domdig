## DOMDig
DOMDig is a DOM XSS scanner that runs inside the Chromium web browser and can scan single page applications (SPA) recursively.
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