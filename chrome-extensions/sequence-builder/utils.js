function pageEval(code, result){
  const wrapped = `(function(){const UI=window.__PROBE__.UI;return ${code}})();`;
  chrome.devtools.inspectedWindow.eval(wrapped, result);
}
  
function onCrawlerMessage(handler){
  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if(message.body){
      handler(message.body);
    }
    sendResponse({status: "ok"});
  });
}