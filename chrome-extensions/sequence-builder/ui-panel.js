
const Modal = class {
  constructor(id, text){
    this.modal = document.createElement('div');
    this.modal.id = id;
    const t = document.createElement('div');
    t.textContent = text;
    this.modal.appendChild(t);
  }

  show(){
    document.body.appendChild(this.modal);
  }
  hide(){
    try{
      document.body.removeChild(this.modal);
    }catch(e){}
  }
}

const modal = new Modal("selectModal", 'Select an element on the page');

onCrawlerMessage( message => {
  if(message.error){
    alert(message.error);
  } else {
    addRow(message.action, message.par1, message.par2);
  }
  modal.hide();
});

document.querySelectorAll('.dropdown-toggle').forEach(e => e.addEventListener('click', function() {
    this.nextElementSibling.style.display = this.nextElementSibling.style.display !== 'block' ? 'block' : 'none';
}));

document.querySelectorAll('.dropdown-item').forEach(e => e.addEventListener('click', function() {
  this.parentNode.style.display = 'none';
}));

document.getElementById("finish-and-scan").addEventListener("click", () => {
  pageEval(`UI.scan(${JSON.stringify(readTables())})`);
});

document.getElementById("finish").addEventListener("click", () => {
  pageEval(`UI.end(${JSON.stringify(readTables())})`);
});

document.getElementById("finish-discart").addEventListener("click", () => {
  if(window.confirm("Discart sequence and exit?")){
    pageEval(`UI.discart()`);
  }
});

document.getElementById("add-action-click").addEventListener("click", () => {
  modal.show();
  pageEval(`UI.selectElement("click")`);
});

document.getElementById("add-action-write").addEventListener("click", () => {
  modal.show();
  pageEval(`UI.selectElement("write")`);
});

document.getElementById("add-action-select").addEventListener("click", () => {
  modal.show();
  pageEval(`UI.selectElement("select")`);
});

document.getElementById("add-action-click-to-navigate").addEventListener("click", () => {
  modal.show();
  pageEval(`UI.selectElement("clickToNavigate")`);
});

document.getElementById("add-action-set-target").addEventListener("click", () => {
  modal.show();
  pageEval(`UI.selectElement("setTarget")`);
});

document.getElementById("add-action-sleep").addEventListener("click", () => {
  addRow("sleep", 1);
});

document.getElementById("add-action-navigate").addEventListener("click", () => {
  addRow("navigate");
});


function readTables() {
    const ret = {start: [], runtime: []};
    for(t of Object.keys(ret)){
        for(let row of document.getElementById(`sequence-table-${t}`).tBodies[0].rows){
            ret[t].push(
                [...row.querySelectorAll("input, select")].map(i => i.value || null)
                .filter(v => v != null)
            );
        }
    }
    return ret.runtime.length > 0 ? ret : ret.start;
  }

async function addRow(action, par1, par2) {
    const table = document.querySelector(".tab-content-active table");
    const updateFields = () => {
      text1.placeholder = "";
      text1.type = "text";
      text2.placeholder = "";
      text2.style.display = 'inline';

      switch (actSelect.value) {
          case "navigate":
              text1.placeholder = "url";
              text2.style.display = 'none';
              break;
          case "write":
              text1.placeholder = "selector";
              text2.placeholder = "text";
              break;
          case "click":
          case "clickToNavigate":
          case "setTarget":
              text1.placeholder = "selector";
              text2.style.display = 'none';
              break;
          case "sleep":
            text1.placeholder = "seconds";
            text1.type = "number";
            text2.style.display = 'none';
      }
    }
    const row = table.tBodies[0].insertRow();

    const actSelect = document.createElement("select");
    ["write", "select", "click", "clickToNavigate", "setTarget", "sleep", "navigate"].forEach(val => {
        const option = document.createElement("option");
        option.value = val;
        option.text = val;
        actSelect.appendChild(option);
    });
    row.insertCell(0).appendChild(actSelect);
    if(action){
      actSelect.value = action;
    }
    const parsCell = row.insertCell(1);
    const text1 = document.createElement("input");
    text1.type = "text";
    const text2 = document.createElement("input");
    text2.type = "text";
    if(par1){
      text1.value = par1;
    }
    if(par2){
      text2.value = par2;
    }

    parsCell.appendChild(text1);
    parsCell.appendChild(document.createElement("br"));
    parsCell.appendChild(text2);

    actSelect.addEventListener('change', () => updateFields());
    updateFields();

    const deleteButton = document.createElement("span");
    deleteButton.style = "color: red; cursor: pointer";
    deleteButton.textContent = "✕";
    deleteButton.onclick = function() {
        table.deleteRow(row.rowIndex);
    };
    row.insertCell(2).appendChild(deleteButton);
}

document.querySelectorAll('.tab-button').forEach(b => {
  b.addEventListener('click', () => {
      const c = b.parentElement.parentElement;
      c.querySelector('.tab-active')?.classList.remove('tab-active');
      c.querySelector('.tab-content-active')?.classList.remove('tab-content-active');
      c.querySelector(`[data-tab-name="${b.getAttribute('data-for')}"]`).classList.add("tab-content-active");
      b.classList.add('tab-active');
  });
});
