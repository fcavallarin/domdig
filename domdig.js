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
var PREVURL = null;
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


async function loadCrawler(vulntype, targetUrl, payload, options, trackUrlChanges){
	var hashSet = false;
	var loaded = false;
	var crawler;
	var checkTempleteInj = true;
	var retries = 4;
	var firstRun = true;

	do{
		if(!CRAWLER || !USE_SINGLE_BROWSER){
			// instantiate htcrawl
			crawler = await htcrawl.launch(targetUrl, options);
			CRAWLER = crawler;
		} else {
			crawler = CRAWLER;
			firstRun = false;
			// await crawler.navigate(targetUrl);
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

		crawler.on("xhr", async function(e, crawler){
			if(options.printRequests){
				utils.printRequest(e.params.request)
			}
			if(DATABASE){
				DATABASE.addRequest(e.params.request);
			}
			return true;
		});

		if(!options.dryRun){
			// set a sink on page scope
			if(payload == null || payload.indexOf(consts.SINKNAME) > -1){
				checkTempleteInj = false;
				crawler.page().exposeFunction(consts.SINKNAME, function(key) {
					var url = "";
					if(crawler.page().url() != PREVURL){
						url = PREVURL = crawler.page().url();
					}
					utils.addVulnerability(VULNSJAR, DATABASE, vulntype, PAYLOADMAP[key], trackUrlChanges ? url : null, null, VERBOSE);
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
					return false;
				});

				// change page hash before the triggering of the first event
				crawler.on("triggerevent", async function(e, crawler){
					if(!hashSet){
						const p = getNewPayload(payload, "hash");
						await crawler.page().evaluate(p => document.location.hash = p, p);
						hashSet = true;
						PREVURL = crawler.page().url();
					}
				});

				if(checkTempleteInj){
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
				await crawler.browser().close();
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

	PREVURL = crawler.page().url();

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

	try{
		// workaround, fix it in htcrawl
		let timeo = setTimeout(function(){
			crawler.stop();
		}, options.maxExecTime);
		await crawler.start();
		clearTimeout(timeo);
	} catch(e){
		console.log(`Error ${e}`);
		process.exit(-4);
	}

}

async function close(crawler){
	await sleep(200);
	if(USE_SINGLE_BROWSER){
		await crawler.page().close();
	}else {
		await crawler.browser().close();
	}
}

async function scanStored(url, options){
	ps("Scanning DOM for stored XSS");
	const crawler = await loadCrawler(consts.VULNTYPE_STORED, url, null, options, true);
	if(crawler == null)return;
	// disable post request since they can overwrite injected payloads
	const cancelPostReq = function(e){return e.params.request.method == "GET"};

	crawler.on("xhr", cancelPostReq);
	crawler.on("fetch", cancelPostReq);
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

function sleep(n){
	return new Promise(resolve => {
		setTimeout(resolve, n);
	});
};

(async () => {
	var targetUrl, cnt, crawler;
	const argv = require('minimist')(process.argv.slice(2), {boolean:["l", "J", "q", "T", "D", "r", "b"]});
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
	var checks = argv.C ? argv.C.split(",") : [consts.CHECKTYPE_DOM, consts.CHECKTYPE_REFLECTED, consts.CHECKTYPE_STORED];
	var payloads = argv.P ? utils.loadPayloadsFromFile(argv.P) : defpayloads.xss;
	if(!argv.T){
		payloads.push(...defpayloads.templateinj);
	}

	if(checks.length == 1 && checks[0] == consts.CHECKTYPE_STORED){
		if(VERBOSE)utils.printWarning("Cannot check for stored without dom or reflected scan. Forcing dom scan.");
		checks.push("dom");
	}
	if(options.singleBrowser){
		USE_SINGLE_BROWSER = true;
	}
	ps("Starting scan");
	if(options.dryRun){
		payloads = ["dontcare"];
		checks = consts.CHECKTYPE_DOM;
		if(VERBOSE)utils.printInfo("Running in dry-run mode, no payloads will be used");
	}

	if(checks.indexOf(consts.CHECKTYPE_DOM) != -1){
		cnt = 1;
		for(let payload of payloads){
			ps("Scanning DOM with " + cnt + " of " + payloads.length + " payloads");
			crawler = await loadCrawler(consts.VULNTYPE_DOM, targetUrl.href, payload, options, true);
			if(crawler == null)continue;
			await scanDom(crawler, options);
			await triggerOnpaste(crawler);
			await scanAttributes(crawler);
			await close(crawler);
			if(checks.indexOf(consts.CHECKTYPE_STORED) != -1){
				await scanStored(targetUrl.href, options);
			}
			ps(cnt + "/" + payloads.length + " payloads checked");
			cnt++;
		}
	}

	// check for reflected XSS
	if(checks.indexOf(consts.CHECKTYPE_REFLECTED) != -1){
		cnt = 1;
		for(let payload of payloads){
			ps("Checking reflected with " + cnt + " of " + payloads.length + " payloads");
			for(let mutUrl of getUrlMutations(targetUrl, payload)){
				let totv = VULNSJAR.length;
				crawler = await loadCrawler(consts.VULNTYPE_REFLECTED, mutUrl.href, payload, options);
				if(crawler == null)continue;
				if(totv != VULNSJAR.length) {
					//ps("Vulnerability found, skipping DOM scan");
				} else {
					await scanDom(crawler, options);
				}
				await triggerOnpaste(crawler);
				await scanAttributes(crawler);
				await close(crawler);
				if(checks.indexOf(consts.CHECKTYPE_STORED) != -1){
					await scanStored(targetUrl.href, options);
				}
				ps(cnt + "/" + payloads.length + " payloads checked (URL mutation: " + mutUrl + ")");
			}
			cnt++;
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
