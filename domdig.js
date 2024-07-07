const fs = require('fs');
const chalk = require('chalk');
const consts = require("./consts");
const htcrawl = require('htcrawl');
const utils = require('./utils');
const defpayloads = require('./payloads');
const URL = require('url').URL;
const Database = require('./database').Database;
const SequenceBuilder = require('./sequence-builder').SequenceBuilder;
const SequenceExecutor = require('./sequence-executor').SequenceExecutor;
const InteractiveUI = require('./interactive-ui').InteractiveUI;

VERBOSE = true;

class DOMDig {
	constructor(){
		this.payloadmap = [];
		this.payloadmap_i = 0;
		this.vulnsjar = [];
		this.database = null;
		this.crawler = null;
		this.targetElement = null;
		this.sequenceExecutor = null;
		this.options = null;
		this.targetUrl = null;
		this.payloads = null;
		this.modes = null;
	}

	getNewPayload(payload, element, info){
		const p = payload.replace("{0}", this.payloadmap_i);
		this.payloadmap[this.payloadmap_i] = {payload:payload, element:element, info:JSON.stringify(info)};
		this.payloadmap_i++;
		return p;
	}

	getUrlMutations(url, payload){
		var nu = new URL(url.href);
		nu.hash = "#" + this.getNewPayload(payload, "hash");
		const muts = [nu];
		for(let p of url.searchParams.keys()){
			nu = new URL(url.href);
			nu.searchParams.set(p, this.getNewPayload(payload, "GET/" + p));
			muts.push(nu);
		}
		return muts;
	}

	async triggerOnpaste(){
		const elems = await this.crawler.page().$$('[onpaste]');
		for(let e of elems){
			await e.evaluate(i => {
				var evt = document.createEvent('HTMLEvents');
				evt.initEvent("paste", true, false);
				i.dispatchEvent(evt);
			});
		}
	}

	async loadHtcrawl(targetUrl){
		if(!this.crawler){
			// instantiate htcrawl
			this.crawler = await htcrawl.launch(targetUrl, this.options);
		} else {
			await this.crawler.newPage(targetUrl);
		}
		if(this.options.localStorage){
			await this.crawler.page().evaluateOnNewDocument( (localStorage) => {
				for(let l of localStorage){
					let fn = l.type == "L" ? window.localStorage : window.sessionStorage;
					fn.setItem(l.key, l.val);
				}
			}, this.options.localStorage);
		}
		await this.crawler.page().setCacheEnabled(false);
		// return crawler;
	}

	fuzzObject(obj, payload) {
		const copies = [];

		const createCopy = (original, path = []) => {
			for (const key in original) {
				if (original.hasOwnProperty(key)) {
					const newPath = path.concat(key);

					if (typeof original[key] === 'object' && original[key] !== null) {
						createCopy(original[key], newPath);
					} else {
						const newObject = structuredClone(obj);
						let current = newObject;

						for (let i = 0; i < newPath.length - 1; i++) {
							current = current[newPath[i]];
						}

						current[newPath[newPath.length - 1]] = payload;
						copies.push(newObject);
					}
				}
			}
		};

		createCopy(obj);
		return copies;
	}

	isFuzzObject(obj) {
		if (typeof obj === 'string' && obj.includes(consts.SINKNAME)) {
			return true;
		}
		if(typeof obj == 'object' && !!obj){
			for (let k in obj) {
				if (this.isFuzzObject(obj[k])) {
					return true;
				}
			}
		}
		return false;
	}


	async loadCrawler(vulntype, targetUrl, payload, setXSSSink, checkTplInj){
		var loaded = false;
		// var crawler;
		var retries = 4;
		do{
			await this.loadHtcrawl(targetUrl);

			const handleRequest = async (e, crawler) => {
				if(this.options.printRequests){
					utils.printRequest(e.params.request)
				}
				if(this.database){
					this.database.addRequest(e.params.request);
				}
				return true;
			};
			this.crawler.on("xhr", handleRequest);
			this.crawler.on("fetch", handleRequest);
			this.crawler.on("navigation", handleRequest);
			this.crawler.on("jsonp", handleRequest);
			this.crawler.on("websocket", handleRequest);

			this.crawler.page().exposeFunction("__domdig_on_postmessage__", async (message, origin, url) => {
				// console.log(message, origin)
				if(this.isFuzzObject(message)){
					return;
				}
				const p = this.getNewPayload(payload, `postMessage/${origin}`)
				const fuzzMessages = this.fuzzObject(message, p);

				const frames = await this.crawler.page().frames();
				let src;
				for(const frame of frames){
					// console.log(frame.url())
					const fu = new URL(frame.url());
					if(fu.origin == origin){
						src = frame;
					}
				}
				src.evaluate( (dst, messages) => {
					if(window.top.location.toString() == dst){
						for(let message of messages){
							window.top.postMessage(message, "*");
						}
					} else {
						window.top.document.querySelectorAll("iframe").forEach(frame => {
							if(frame.contentWindow.document.location.toString() == dst){
								for(let message of messages){
									frame.contentWindow.postMessage(message, "*");
								}
							}
						})
					}
				}, url, fuzzMessages);
			})
			this.crawler.page().evaluateOnNewDocument(() => {
				window.addEventListener("message", async event => {
					await window.__domdig_on_postmessage__(event.data, event.origin, `${document.location}`);
				});
			});
			this.crawler.page().on("frameattached", async frame => {
				try{
					await frame.evaluate(() => {
						window.addEventListener("message", async event => {
							await window.__domdig_on_postmessage__(event.data, event.origin, `${document.location}`);
						});
					});
				}catch(e){}
			});
			if(!this.options.dryRun){
				if(setXSSSink){
					this.crawler.page().exposeFunction(consts.SINKNAME, (key) => {
						const url = this.crawler.page().url();
						var confirmed = true;
						// When searching for DOM XSS, we need to check if the current URL has changed and contais our payload.
						if(vulntype == consts.VULNTYPE_DOM){
							confirmed = url.match(consts.SINKNAME) != null;
						}
						utils.addVulnerability(this.vulnsjar, this.database, vulntype, this.payloadmap[key], url, null, VERBOSE, confirmed);
					});
				}

				if(payload != null){
					// fill all inputs with a payload
					this.crawler.on("fillinput", async (e, crawler) => {
						const p = this.getNewPayload(payload, e.params.element);
						try{
							await crawler.page().$eval(e.params.element, (i, p) => i.value = p, p);

							// return false to prevent element to be automatically filled with a random value
							// we need to manually trigger angularjs 'input' event that won't be triggered by htcrawl (due to return false)
							await crawler.page().$eval(e.params.element, el => {
								const evt = document.createEvent('HTMLEvents');
								evt.initEvent("input", true, false);
								el.dispatchEvent(evt);
							});
						}catch(e){}
						return false;
					});

					if(checkTplInj){
						this.crawler.on("eventtriggered", async (e, crawler) => {
							var cont = await crawler.page().content();
							var re = /\[object [A-Za-z]+\]([0-9]+)\[object [A-Za-z]+\]/gm;
							var m;
							while(m=re.exec(cont)){
								var key = m[1];
								utils.addVulnerability(this.vulnsjar, this.database, consts.VULNTYPE_TEMPLATEINJ, this.payloadmap[key], null, null, VERBOSE);
							}
						});
					}
				}
			}

			try{
				await this.crawler.load();
				loaded = true;
			} catch(e){
				try{
					await this.close();
				} catch(e1){}
				utils.printError(`${e}`);
				if(retries > 0){
					retries--;
					if(VERBOSE) utils.printInfo("Retrying . . .");
				} else {
					if(VERBOSE) utils.printError("Payload skipped!");
					return null;
				}
			}
		} while(!loaded);

		if(this.sequenceExecutor){
			try{
				await this.sequenceExecutor.run(this.crawler, "runtime");
			}catch(e){
				if(this.database){
					this.database.updateStatus(`${e}`, true);
				}
				if(VERBOSE) utils.printError(`Runtime sequence error: ${e}`);
				return null;
			}
		}
	}

	async scanDom(){
		let timeo = setTimeout(function(){
			this.crawler.stop();
		}, this.options.maxExecTime);
		let target = null;
		if(this.targetElement){
			this.ps(`Scanning ${this.targetElement}`);
			target = await this.crawler.page().$(this.targetElement);
		}
		await this.crawler.start(target);
		clearTimeout(timeo);
	}

	async close(){
		await utils.sleep(200);
		try{
			await this.crawler.page().close();
		}catch(e){}
	}

// Must run after an XSS scan (DOM or reflected) since it just checks if a payload,
// set by the prev scan, persists
	async scanStored(url){
		this.ps("Scanning DOM for stored XSS");
		await this.loadCrawler(consts.VULNTYPE_STORED, url, null, true, false);
		if(this.crawler == null)return;
		// disable post request since they can overwrite injected payloads
		const cancelPostReq = function(e){return e.params.request.method == "GET"};
		this.crawler.on("xhr", cancelPostReq);
		this.crawler.on("fetch", cancelPostReq);
		// Do not fill inputs with payloads, it's just a crawling.
		this.crawler.on("fillinput", () => true);
		await this.scanDom();
		await this.triggerOnpaste();
		await this.close();
		this.ps("Stored XSS scan finshed");
	}

	ps(message, completed){
		if(VERBOSE)utils.printStatus(message);
		if(this.database){
			this.database.updateStatus(message, !!completed);
		}
	}

	async crawlDOM(){
		this.crawler.on("fillinput", () => true);
		try{
			await this.scanDom();
		}catch(e){

		}
	}

	async retryScan(retries, fnc){
		while(true) try{
			await fnc();
			break;
		} catch(ex){
			if(retries > 0){
				retries--;
				try{
					await this.crawler.page().close();
				}catch(e){}
				utils.printWarning("Unexpected error, retrying..." + ex);
				continue;
			} else {
				throw(ex);
			}
		}
	}

	async runDOMScan(payloads, targetUrl, isTplInj){
		var cnt = 1;

		for(let payload of payloads){
			await this.retryScan(4, async () => {
				this.ps(`Domscan scanning for ${isTplInj ? "Template Injection" : "DOM XSS"} with ${cnt} of ${payloads.length} payloads`);
				await this.loadCrawler(consts.VULNTYPE_DOM, targetUrl.href, payload, !isTplInj, isTplInj);

				if(this.crawler == null)return;

				await this.scanDom();
				await this.triggerOnpaste();
				await this.close();

				if(this.options.scanStored){
					await this.scanStored(targetUrl.href);
				}
				this.ps(cnt + "/" + payloads.length + " payloads checked");
				cnt++;
			});
		}
	}

	async runFuzzer(payloads, targetUrl, isTplInj){
		var cnt = 1;
		for(let payload of payloads){
			this.ps(`Fuzzer scanning for ${isTplInj ? "Template Injection" : "DOM XSS"} with ${cnt} of ${payloads.length} payloads`);
			for(let mutUrl of this.getUrlMutations(targetUrl, payload)){
				await this.retryScan(4, async () => {

					let totv = this.vulnsjar.length;
					await this.loadCrawler(consts.VULNTYPE_DOM, mutUrl.href, payload, !isTplInj, isTplInj);
					if(this.crawler == null)return;
					// If, after load, a new vuln is found (this.vulnsjar.length increased), then the DOM scan can be skipped.
					if(totv == this.vulnsjar.length) {
						// Do not fill inputs with payloads, it's just a crawling.
						this.crawler.on("fillinput", () => true);
						await this.scanDom();
					}
					await this.triggerOnpaste();
					await this.close();

					if(this.options.scanStored){
						await this.scanStored(targetUrl.href);
					}
					this.ps(cnt + "/" + payloads.length + " payloads checked (URL mutation: " + utils.replaceSinkName(mutUrl.href) + ")");
				});
			}
			cnt++;
		}
	}

	async startScan() {
		let modes = this.modes;
		this.ps(`Starting scan\n    modes: ${modes.join(",")}  scan stored: ${this.options.scanStored ? "yes" : "no"}   check template injection: ${this.options.checkTemplateInj ? "yes" : "no"}`);
		if(this.options.dryRun){
			// Crawl the DOM with all sinks enabled
			modes = allModes;
			await this.loadCrawler(consts.VULNTYPE_DOM, this.targetUrl.href, "payload", true, true);
			if(this.crawler == null){
				throw("Error loading crawler");
			};
			if(VERBOSE)utils.printInfo("Running in dry-run mode, no payloads will be used");
			await this.crawlDOM();
		}else {
			if(modes.indexOf(consts.MODE_DOMSCAN) != -1){
				await this.runDOMScan(this.payloads, this.targetUrl, false);
				if(this.options.checkTemplateInj){
					await this.runDOMScan(defpayloads.templateinj, this.targetUrl, true);
				}
			}

			if(modes.indexOf(consts.MODE_FUZZ) != -1){
				await this.runFuzzer(this.payloads, this.targetUrl, false);
				if(this.options.checkTemplateInj){
					await this.runFuzzer(defpayloads.templateinj, this.targetUrl, true);
				}
			}
		}
		if(VERBOSE)console.log("");
		this.ps("Scan finished, tot vulnerabilities: " + this.vulnsjar.length, true);

		if(this.options.printJson){
			console.log(utils.prettifyJson(this.vulnsjar));
		} else if(VERBOSE){
			for(let v of this.vulnsjar){
				utils.printVulnerability(v);
			}
		}

		process.exit(0);
	}

	async run() {
		const argv = require('minimist')(process.argv.slice(2), {
			boolean:["l", "J", "q", "T", "D", "r", "S", "O", "i"]
		});
		if(argv.q)VERBOSE = false;
		if(VERBOSE)utils.banner();
		if('h' in argv){
			utils.usage();
			process.exit(0);
		}
		if(argv._.length == 0){
			utils.usage();
			process.exit(1);
		}

		try{
			this.targetUrl = new URL(argv._[0]);
		} catch(e){
			utils.error(e);
		}
		const {options, settings} = utils.parseArgs(argv, this.targetUrl);
		this.options = options;
		if(argv.m){
			settings.push(["-m", argv.m])
		}
		settings.push([null, this.targetUrl.href]);
		options.crawlmode = "random";
		if(options.databaseFileName){
			if(fs.existsSync(options.databaseFileName)){
				utils.error(`File ${options.databaseFileName} already exists`);
				process.exit(1);
			}
			this.database = new Database(options.databaseFileName);
			this.database.init();
			this.database.addScanArguments(settings);
		}
		if(!options.maxExecTime) options.maxExecTime = consts.DEF_MAXEXECTIME;
		const allModes = [consts.MODE_DOMSCAN, consts.MODE_FUZZ];
		this.modes = argv.m ?  argv.m.split(",") : allModes;
		for(let mode of this.modes){
			if(allModes.indexOf(mode) == -1){
				utils.error(`Mode "${mode}" not found. Modes are: ${allModes.join(",")}.`);
				process.exit(1);
			}
		}

		this.payloads = argv.P ? utils.loadPayloadsFromFile(argv.P) : defpayloads.xss;

		const sigHandler = () => {
			console.log("Terminating...");
			process.exit(0);
		};

		process.on('SIGTERM', sigHandler);
		process.on('SIGINT', sigHandler);

		if(options.sequenceBuilder){
			if(fs.existsSync(options.sequenceBuilder)){
				utils.printError(`${options.sequenceBuilder} already exists`);
				process.exit(1);
			}
			this.ps("Running Sequence Builder, use Domdig's DevTools panel ...");
			const builder = new SequenceBuilder(this.targetUrl.href, options);
			const builderResult = await builder.run();
			if(builderResult.discart){
				process.exit(0);
			}
			fs.writeFileSync(options.sequenceBuilder, JSON.stringify(builderResult.sequence));
			this.ps(`Sequence saved to ${options.sequenceBuilder}`);
			if(builderResult.next == "scan"){
				options.initSequence = builderResult.sequence;
				if(builderResult.targetUrl){
					this.targetUrl.href = builderResult.targetUrl;
				}
			} else {
				process.exit(0);
			}
		}

		if(this.options.initSequence){
			try{
				this.sequenceExecutor = new SequenceExecutor(options.initSequence, status => this.ps(status));
				if(this.sequenceExecutor.sequence.start.length > 0){
					await this.loadHtcrawl(this.targetUrl.href);
					await this.sequenceExecutor.run(this.crawler, "start");
					await this.crawler.page().close();
				}
			}catch(e){
				if(this.database){
					this.database.updateStatus(`${e}`, true);
				}
				console.error(chalk.red(`${e}`));
				process.exit(2);
			}
		}
		if(this.options.interactiveUI){
			this.ps("Running in interactive, use Domdig's DevTools panel ...");
			const interactiveUI = new InteractiveUI(this);
			this.crawler = await htcrawl.launch(this.targetUrl.href, {
				...this.options,
				headlessChrome: false,
				customUI: interactiveUI.customUI
			});
			await this.crawler.load();
		} else {
			await this.startScan();
		}
	}
}

(async () =>{
	const domDig = new DOMDig();
	await domDig.run();
})();
