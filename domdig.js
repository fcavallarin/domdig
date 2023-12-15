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

const PAYLOADMAP = [];
var PAYLOADMAP_I = 0;
const VULNSJAR = [];
var VERBOSE = true;
var DATABASE = null;
var CRAWLER = null;
var USE_SINGLE_BROWSER = false;
var TARGET_ELEMENT = null;
var SEQUENCE_EXECUTOR = null;

function getNewPayload(payload, element, info){
	const p = payload.replace("{0}", PAYLOADMAP_I);
	PAYLOADMAP[PAYLOADMAP_I] = {payload:payload, element:element, info:JSON.stringify(info)};
	PAYLOADMAP_I++;
	return p;
}

function getUrlMutations(url, payload){
	var nu = new URL(url.href);
	nu.hash = "#" + getNewPayload(payload, "hash");
	const muts = [nu];
	for(let p of url.searchParams.keys()){
		nu = new URL(url.href);
		nu.searchParams.set(p, getNewPayload(payload, "GET/" + p));
		muts.push(nu);
	}
	return muts;
}

async function triggerOnpaste(crawler){
	const elems = await crawler.page().$$('[onpaste]');
	for(let e of elems){
		await e.evaluate(i => {
			var evt = document.createEvent('HTMLEvents');
			evt.initEvent("paste", true, false);
			i.dispatchEvent(evt);
		});
	}
}

async function loadHtcrawl(targetUrl, options){
	if(!CRAWLER || !USE_SINGLE_BROWSER){
		// instantiate htcrawl
		crawler = await htcrawl.launch(targetUrl, options);
		CRAWLER = crawler;
	} else {
		crawler = CRAWLER;
		firstRun = false;
		await crawler.newPage(targetUrl);
	}
	if(options.localStorage){
		await crawler.page().evaluateOnNewDocument( (localStorage) => {
			for(let l of localStorage){
				let fn = l.type == "L" ? window.localStorage : window.sessionStorage;
				fn.setItem(l.key, l.val);
			}
		}, options.localStorage);
	}
	await crawler.page().setCacheEnabled(false);
	return crawler;
}

function fuzzObject(obj, payload) {
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

function isFuzzObject(obj) {
	if (typeof obj === 'string' && obj.includes(consts.SINKNAME)) {
		return true;
	}
	if(typeof obj == 'object' && !!obj){
		for (let k in obj) {
			if (isFuzzObject(obj[k])) {
				return true;
			}
		}
	}
    return false;
}


async function loadCrawler(vulntype, targetUrl, payload, setXSSSink, checkTplInj, options){
	var loaded = false;
	var crawler;
	var retries = 4;
	do{
		crawler = await loadHtcrawl(targetUrl, options);

		const handleRequest = async function(e, crawler){
			if(options.printRequests){
				utils.printRequest(e.params.request)
			}
			if(DATABASE){
				DATABASE.addRequest(e.params.request);
			}
			return true;
		};
		crawler.on("xhr", handleRequest);
		crawler.on("fetch", handleRequest);
		crawler.on("navigation", handleRequest);
		crawler.on("jsonp", handleRequest);
		crawler.on("websocket", handleRequest);

		crawler.page().exposeFunction("__domdig_on_postmessage__", async (message, origin, url) => {
			// console.log(message, origin)
			if(isFuzzObject(message)){
				return;
			}
			const p = getNewPayload(payload, `postMessage/${origin}`)
			const fuzzMessages = fuzzObject(message, p);

			const frames = await crawler.page().frames();
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
		crawler.page().evaluateOnNewDocument(() => {
			window.addEventListener("message", async event => {
				await window.__domdig_on_postmessage__(event.data, event.origin, `${document.location}`);
			});
		});
		crawler.page().on("frameattached", async frame => {
			try{
				await frame.evaluate(() => {
					window.addEventListener("message", async event => {
						await window.__domdig_on_postmessage__(event.data, event.origin, `${document.location}`);
					});
				});
			}catch(e){}
		});
		if(!options.dryRun){
			if(setXSSSink){
				crawler.page().exposeFunction(consts.SINKNAME, function(key) {
					const url = crawler.page().url();
					var confirmed = true;
					// When searching for DOM XSS, we need to check if the current URL has changed and contais our payload.
					if(vulntype == consts.VULNTYPE_DOM){
						confirmed = url.match(consts.SINKNAME) != null;
					}
					utils.addVulnerability(VULNSJAR, DATABASE, vulntype, PAYLOADMAP[key], url, null, VERBOSE, confirmed);
				});
			}

			if(payload != null){
				// fill all inputs with a payload
				crawler.on("fillinput", async function(e, crawler){
					const p = getNewPayload(payload, e.params.element);
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
					crawler.on("eventtriggered", async function(e, crawler){
						var cont = await crawler.page().content();
						var re = /\[object [A-Za-z]+\]([0-9]+)\[object [A-Za-z]+\]/gm;
						var m;
						while(m=re.exec(cont)){
							var key = m[1];
							utils.addVulnerability(VULNSJAR, DATABASE, consts.VULNTYPE_TEMPLATEINJ, PAYLOADMAP[key], null, null, VERBOSE);
						}
					});
				}
			}
		}

		try{
			await crawler.load();
			loaded = true;
		} catch(e){
			try{
				await close(crawler);
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

	if(SEQUENCE_EXECUTOR){
		try{
			await SEQUENCE_EXECUTOR.run(crawler, "runtime");
		}catch(e){
			if(DATABASE){
				DATABASE.updateStatus(`${e}`, true);
			}
			if(VERBOSE) utils.printError(`Runtime sequence error: ${e}`);
			return null;
		}
	}

	return crawler;
}




async function scanDom(crawler, options){
	let timeo = setTimeout(function(){
		crawler.stop();
	}, options.maxExecTime);
	let target = null;
	if(TARGET_ELEMENT){
		ps(`Scanning ${TARGET_ELEMENT}`);
		target = await crawler.page().$(TARGET_ELEMENT);
	}
	await crawler.start(target);
	clearTimeout(timeo);

}

async function close(crawler){
	await utils.sleep(200);
	try{
		if(USE_SINGLE_BROWSER){
			await crawler.page().close();
		}else {
			await crawler.browser().close();
		}
	}catch(e){}
}

// Must run after an XSS scan (DOM or reflected) since it just checks if a payload,
// set by the prev scan, persists
async function scanStored(url, options){
	ps("Scanning DOM for stored XSS");
	const crawler = await loadCrawler(consts.VULNTYPE_STORED, url, null, true, false, options);
	if(crawler == null)return;
	// disable post request since they can overwrite injected payloads
	const cancelPostReq = function(e){return e.params.request.method == "GET"};
	crawler.on("xhr", cancelPostReq);
	crawler.on("fetch", cancelPostReq);
	// Do not fill inputs with payloads, it's just a crawling.
	crawler.on("fillinput", () => true);
	await scanDom(crawler, options);
	await triggerOnpaste(crawler);
	await close(crawler);
	ps("Stored XSS scan finshed");
}

function ps(message, completed){
	if(VERBOSE)utils.printStatus(message);
	if(DATABASE){
		DATABASE.updateStatus(message, !!completed);
	}
}

async function crawlDOM(crawler, options){
	crawler.on("fillinput", () => true);
	try{
		await scanDom(crawler, options);
	}catch(e){

	}
}

async function retryScan(retries, fnc){
	while(true) try{
		await fnc();
		break;
	} catch(ex){
		if(retries > 0){
			retries--;
			if(CRAWLER){
				try{
					await CRAWLER.browser().close();
				}catch(e){}
				CRAWLER = null;
			}
			utils.printWarning("Unexpected error, retrying..." + ex);
			continue;
		} else {
			throw(ex);
		}
	}
}

async function runDOMScan(payloads, targetUrl, isTplInj, options){
	var cnt = 1;

	for(let payload of payloads){
		await retryScan(4, async () => {
			ps(`Domscan scanning for ${isTplInj ? "Template Injection" : "DOM XSS"} with ${cnt} of ${payloads.length} payloads`);
			const crawler = await loadCrawler(consts.VULNTYPE_DOM, targetUrl.href, payload, !isTplInj, isTplInj, options);
			if(crawler == null)return;
			await scanDom(crawler, options);
			await triggerOnpaste(crawler);
			await close(crawler);

			if(options.scanStored){
				await scanStored(targetUrl.href, options);
			}
			ps(cnt + "/" + payloads.length + " payloads checked");
			cnt++;
		});
	}
}

async function runFuzzer(payloads, targetUrl, isTplInj, options){
	var cnt = 1;
	for(let payload of payloads){
		ps(`Fuzzer scanning for ${isTplInj ? "Template Injection" : "DOM XSS"} with ${cnt} of ${payloads.length} payloads`);
		for(let mutUrl of getUrlMutations(targetUrl, payload)){
			await retryScan(4, async () => {

				let totv = VULNSJAR.length;
				const crawler = await loadCrawler(consts.VULNTYPE_DOM, mutUrl.href, payload, !isTplInj, isTplInj, options);
				if(crawler == null)return;
				// If, after load, a new vuln is found (VULNSJAR.length increased), then the DOM scan can be skipped.
				if(totv == VULNSJAR.length) {
					// Do not fill inputs with payloads, it's just a crawling.
					crawler.on("fillinput", () => true);
					await scanDom(crawler, options);
				}
				await triggerOnpaste(crawler);
				await close(crawler);

				if(options.scanStored){
					await scanStored(targetUrl.href, options);
				}
				ps(cnt + "/" + payloads.length + " payloads checked (URL mutation: " + utils.replaceSinkName(mutUrl.href) + ")");
			});
		}
		cnt++;
	}
}


(async () => {
	var targetUrl, cnt, crawler;
	const argv = require('minimist')(process.argv.slice(2), {boolean:["l", "J", "q", "T", "D", "r", "B", "S", "O"]});
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
		targetUrl = new URL(argv._[0]);
	} catch(e){
		utils.error(e);
	}
	const {options, settings} = utils.parseArgs(argv, targetUrl);
	if(argv.m){
		settings.push(["-m", argv.m])
	}
	settings.push([null, targetUrl.href]);
	options.crawlmode = "random";
	if(options.databaseFileName){
		if(fs.existsSync(options.databaseFileName)){
			utils.error(`File ${options.databaseFileName} already exists`);
			process.exit(1);
		}
		DATABASE = new Database(options.databaseFileName);
		DATABASE.init();
		DATABASE.addScanArguments(settings);
	}
	if(!options.maxExecTime) options.maxExecTime = consts.DEF_MAXEXECTIME;
	const allModes = [consts.MODE_DOMSCAN, consts.MODE_FUZZ];
	var modes = argv.m ?  argv.m.split(",") : allModes;
	for(let mode of modes){
		if(allModes.indexOf(mode) == -1){
			utils.error(`Mode "${mode}" not found. Modes are: ${allModes.join(",")}.`);
			process.exit(1);
		}
	}
	if(argv.C){
		utils.error("-C option is deprecated. See -T -S and -m");
		process.exit(1);
	}
	var payloads = argv.P ? utils.loadPayloadsFromFile(argv.P) : defpayloads.xss;

	if(options.singleBrowser){
		USE_SINGLE_BROWSER = true;
	}

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
		ps("Running Sequence Builder, use Domdig's DevTools panel ...");
		const builder = new SequenceBuilder(targetUrl.href, options);
		const builderResult = await builder.run();
		if(builderResult.discart){
			process.exit(0);
		}
		fs.writeFileSync(options.sequenceBuilder, JSON.stringify(builderResult.sequence));
		ps(`Sequence saved to ${options.sequenceBuilder}`);
		if(builderResult.next == "scan"){
			options.initSequence = builderResult.sequence;
			if(builderResult.targetUrl){
				targetUrl.href = builderResult.targetUrl;
			}
		} else {
			process.exit(0);
		}
	}

	if(options.initSequence){
		try{
			SEQUENCE_EXECUTOR = new SequenceExecutor(options.initSequence, status => ps(status));
			if(SEQUENCE_EXECUTOR.sequence.start.length > 0){
				const seqCrawler = await loadHtcrawl(targetUrl.href, options);
				await seqCrawler.load();
				await SEQUENCE_EXECUTOR.run(seqCrawler, "start");
				await seqCrawler.page().close();
			}
		}catch(e){
			if(DATABASE){
				DATABASE.updateStatus(`${e}`, true);
			}
			console.error(chalk.red(`${e}`));
			process.exit(2);
		}
	}

	ps(`Starting scan\n    modes: ${modes.join(",")}  scan stored: ${options.scanStored ? "yes" : "no"}   check template injection: ${options.checkTemplateInj ? "yes" : "no"}`);

	if(options.dryRun){
		// Crawl the DOM with all sinks enabled
		modes = allModes;
		const crawler = await loadCrawler(consts.VULNTYPE_DOM, targetUrl.href, "payload", true, true, options);
		if(crawler == null){
			throw("Error loading crawler");
		};
		if(VERBOSE)utils.printInfo("Running in dry-run mode, no payloads will be used");
		await crawlDOM(crawler, options);
	}else {

		if(modes.indexOf(consts.MODE_DOMSCAN) != -1){
			await runDOMScan(payloads, targetUrl, false, options);
			if(options.checkTemplateInj){
				await runDOMScan(defpayloads.templateinj, targetUrl, true, options);
			}
		}

		if(modes.indexOf(consts.MODE_FUZZ) != -1){
			await runFuzzer(payloads, targetUrl, false, options);
			if(options.checkTemplateInj){
				await runFuzzer(defpayloads.templateinj, targetUrl, true, options);
			}
		}
	}
	if(VERBOSE)console.log("");
	ps("Scan finished, tot vulnerabilities: " + VULNSJAR.length, true);

	if(argv.J){
		console.log(utils.prettifyJson(VULNSJAR));
	} else if(VERBOSE){
		for(let v of VULNSJAR){
			utils.printVulnerability(v);
		}
	}

	if(argv.o){
		let fn = utils.writeJSON(argv.o, VULNSJAR);
		ps("Findings saved to " + fn)
	}
	process.exit(0);
})();
