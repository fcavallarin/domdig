const consoleLog = (message) => {
    const c = document.getElementById("console");
    c.innerText += "\n" + message;
    c.scrollTop = c.scrollHeight;
}

onCrawlerMessage( message => {
  consoleLog(message);
});

document.getElementById('start').onclick = () => {
  pageEval("UI.start()");
};

document.getElementById('scan-selected').onclick = () => {
  consoleLog("Select the element to scan");
  pageEval("UI.scanElement()");
};

document.getElementById('login').onclick = () => {
  pageEval("UI.login()")
};

document.getElementById('clear-console').onclick = () => {
  document.getElementById('console').innerText = "";
};
