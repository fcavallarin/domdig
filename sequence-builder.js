const fs = require('fs');
const chalk = require('chalk');
const consts = require("./consts");
const htcrawl = require('htcrawl');
const utils = require('./utils');


exports.SequenceBuilder = class {
	constructor(url, options){
		this.url = url;
        this.options = options;
        this.crawler = null;
        this.targetUrl = null;
        this._finished = false;
	}

    run(){
        return new Promise((resolve, reject) => {
            this.launch(resolve);
        });
    }
    async launch(resolve){
        this.crawler = await htcrawl.launch(this.url, {
            ...this.options,
            headlessChrome: false,
            customUI: {
                extensionPath: __dirname + '/chrome-extensions/sequence-builder',
                UIMethods: UI => {
                    UI.selectElement = async action => {
                        const e = await UI.utils.selectElement();
                        switch(action){
                            case "click":
                            case "clickToNavigate":
                            case "setTarget":
                                UI.dispatch('selectElement', {action: action, par1: e.selector});
                                break;
                            case "write":
                            case "select":
                                let inp = e.element;
                                if(!inp.matches("input, select, textarea")){
                                    inp = inp.querySelector("input, select, textarea");
                                }
                                if(!inp){
                                    UI.dispatch('selectElement', {error: "Cannot find an input element"});
                                }

                                const inpRect = inp.getBoundingClientRect();
                                const okBtn = UI.utils.createElement("button", {
                                    position: 'absolute',
                                    left: (inpRect.left + document.documentElement.scrollLeft + inpRect.width) + "px",
                                    top: (inpRect.top + document.documentElement.scrollTop) + "px",
                                    backgroundColor: '#9c27b0',
                                    color: 'white',
                                    border: 'none',
                                    padding: '10px 20px',
                                    borderRadius: '5px',
                                    cursor: 'pointer',
                                    zIndex: 2147483640
                                });
                                okBtn.textContent = "Apply";
                                inp.focus();
                                okBtn.onclick = function() {
                                    this.parentNode.removeChild(this);
                                    UI.dispatch('selectElement', {
                                        action: action,
                                        par1: UI.utils.getElementSelector(inp),
                                        par2: inp.value
                                    });
                                };
                                break;
                        }
                    };
                    UI.end = sequence => {
                        UI.dispatch("end", {sequence: sequence});
                    };

                    UI.scan = sequence => {
                        UI.dispatch("scan", {sequence: sequence});
                    };

                    UI.discart = () => {
                        UI.dispatch("discart");
                    };
                },
                events: {
                    selectElement: async e => {
                        this.crawler.sendToUI(e.params);
                        if(e.params.action == "click"){
                            await this.crawler.page().click(e.params.par1);
                        }
                        if(e.params.action == "clickToNavigate"){
                            try{
                                this.crawler.on("navigation", e => {
                                    this.targetUrl = e.params.request.url;
                                });
                                await this.crawler.clickToNavigate(e.params.par1);
                            }catch(e){
                                this.crawler.sendToUI({error: "Navigation timeout"});
                                return;
                            }
                        }
                    },
                    end: async e => {
                        this.crawler.browser().close();
                        resolve({
                            sequence: e.params.sequence,
                            next: null
                        });
                    },
                    scan: async e => {
                        this.crawler.browser().close();
                        resolve({
                            sequence: e.params.sequence,
                            next: "scan",
                            targetUrl: this.targetUrl,
                        });
                    },
                    discart: async e => {
                        resolve({discart: true});
                    },
                }
            },
        });
        await this.crawler.load();
        this.crawler.sendToUI({action: "navigate", par1: this.url});
    }
};