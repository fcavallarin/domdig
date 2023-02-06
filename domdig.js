const fs = require('fs');
const chalk = require('chalk');
const consts = require("./consts");
const htcrawl = require('htcrawl');
const utils = require('./utils');
const defpayloads = require('./payloads');
const URL = require('url').URL;
const Database = require('./database').Database;

const PAYLOADMAP = [];
var PAYLOADMAP_I = 0;
const VULNSJAR = [];
var VERBOSE = true;
var DATABASE = null;
var CRAWLER = null;
var USE_SINGLE_BROWSER = false;

function getNewPayload(payload, element){
	const p = payload.replace("{0}", PAYLOADMAP_I);
	PAYLOADMAP[PAYLOADMAP_I] = {payload:payload, element:element};
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

async function scanAttributes(crawler){
	// use also 'srcdoc' since it can contain also esacped html: <iframe srcdoc="&lt;img src=1 onerror=alert(1)&gt;"></iframe>
	// content can have a "timer" so maybe is not executed in time
	const attrs = ["href", "action", "formaction", "srcdoc", "content"];
	for(let attr of attrs){
		const elems = await crawler.page().$$(`[${attr}]`);
		for(let e of elems){
			// must use evaluate since puppetteer cannot get non-standard attributes
			let val = await e.evaluate( (i,a) => i.getAttribute(a), attr);
			if(val.startsWith(consts.SINKNAME) == false){
				continue;
			} else {
				let key = val.match(/\(([0-9]+)\)/)[1];
				let es = await utils.getElementSelector(e);
				utils.addVulnerability(VULNSJAR, DATABASE, consts.VULNTYPE_WARNING, PAYLOADMAP[key], null, `Attribute '${attr}' of '${es}' set to payload`, VERBOSE);
				break;
			}
		}
	}
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

function sequenceError(message, seqline){
	if(seqline){
		message = "action " + seqline + ": " + message;
	}
	if(DATABASE){
		DATABASE.updateStatus(message, true);
	}
	console.error(chalk.red(message));
	process.exit(2);
}

async function loadCrawler(vulntype, targetUrl, payload, setXSSSink, checkTplInj, options){
	// var hashSet = false;
	var loaded = false;
	var crawler;
	var retries = 4;
	var firstRun = true;
	//options.openChromeDevtoos = true;
	do{
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
					}catch(e){}
					// return false to prevent element to be automatically filled with a random value
					// we need to manually trigger angularjs 'input' event that won't be triggered by htcrawl (due to return false)
					crawler.page().$eval(e.params.element, el => {
						const evt = document.createEvent('HTMLEvents');
						evt.initEvent("input", true, false);
						el.dispatchEvent(evt);
					});
					return false;
				});

				// change page hash before the triggering of the first event
				// to see if some code, during crawling, takes the hash and evaluates our payload
				// It will result in a sort of assisted-XSS where the victim, after following the XSS URL, 
				// has to perform some actions.
				// It's useless since the same (a better) test is performed by the Reflected XSS check.
				// crawler.on("triggerevent", async function(e, crawler){
				// 	if(!hashSet){
				// 		const p = getNewPayload(payload, "hash");
				// 		await crawler.page().evaluate(p => document.location.hash = p, p);
				// 		hashSet = true;
				// 		PREVURL = crawler.page().url();
				// 	}
				// });

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

	if(options.initSequence  && firstRun){
		ps(`Start initial sequence`);
		let seqline = 1;
		for(let seq of options.initSequence){
			switch(seq[0]){
				case "sleep":
					ps(`Sleep for ${seq[1]} seconds`);
					await sleep(seq[1] * 1000);
					break;
				case "write":
					ps(`Filling input ${seq[1]} with "${seq[2]}"`);
					try{
						await crawler.page().type(seq[1], seq[2]);
					} catch(e){
						sequenceError("element not found", seqline);
					}
					break;
				case "click":
					ps(`Click ${seq[1]}`);
					try{
						await crawler.page().click(seq[1]);
					} catch(e){
						sequenceError("element not found", seqline);
					}
					await crawler.waitForRequestsCompletion();
					break;
				case "clickToNavigate":
					ps(`Click to navigate ${seq[1]} ${seq[2]}`);
					try{
						await crawler.clickToNavigate(seq[1], seq[2]);
					} catch(err){
						sequenceError(err, seqline);
					}
					break;
				case "navigate":
					ps(`Navigate ${seq[1]}`);
					try{
						await crawler.navigate(seq[1]);
					} catch(err){
						sequenceError(err, seqline);
					}
					break;
				default:
					sequenceError("action not found", seqline);
			}
			seqline++;
		}
		ps(`Initial sequence finished`);
	}

	return crawler;
}

async function scanDom(crawler, options){
	let timeo = setTimeout(function(){
		crawler.stop();
	}, options.maxExecTime);
	await crawler.start();
	clearTimeout(timeo);

}

async function close(crawler){
	await sleep(200);
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
	await scanAttributes(crawler);
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

function sleep(n){
	return new Promise(resolve => {
		setTimeout(resolve, n);
	});
};


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
			await scanAttributes(crawler);

			// Last chance, let's try to change the hash
			// await crawler.page().evaluate(p => document.location.hash = p, getNewPayload(payload, "hash"));
			// await triggerOnpaste(crawler);
			// await scanAttributes(crawler);

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
				await scanAttributes(crawler);
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
	const argv = require('minimist')(process.argv.slice(2), {boolean:["l", "J", "q", "T", "D", "r", "B", "S"]});
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
	const options = utils.parseArgs(argv, targetUrl);
	options.crawlmode = "random";
	if(options.databaseFileName){
		if(fs.existsSync(options.databaseFileName)){
			utils.error(`File ${options.databaseFileName} already exists`);
			process.exit(1);
		}
		DATABASE = new Database(options.databaseFileName);
		DATABASE.init();
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
