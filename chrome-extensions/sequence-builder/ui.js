let domdiglPanel;
chrome.devtools.panels.create(
    "Domdig",
    "",
    "ui-panel.html",
    function(panel) {
        domdiglPanel = panel;
    }
  );
  