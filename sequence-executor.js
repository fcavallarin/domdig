const fs = require('fs');
const chalk = require('chalk');
const consts = require("./consts");
const htcrawl = require('htcrawl');
const utils = require('./utils');


exports.SequenceExecutor = class {
    seqline;
    result = {};
    constructor(sequence, statusChange){
        this.sequence = Array.isArray(sequence) ? {start: sequence, runtime: []} : sequence;
        this.statusChange = statusChange;
    }

   async run(crawler, sequenceType) {
        this.seqline = 1;
        this.result.targetElement = null;
        const sequence = this.sequence[sequenceType];
        if(sequence.length == 0){
            return
        }
        this.statusChange(`Running sequence: ${sequenceType}`);
        for(let seq of sequence){
            switch(seq[0]){
                case "sleep":
                    this.statusChange(`Sleep for ${seq[1]} seconds`);
                    await utils.sleep(seq[1] * 1000);
                    break;
                case "write":
                    this.statusChange(`Filling input ${seq[1]} with "${seq[2]}"`);
                    try{
                        await crawler.page().type(seq[1], seq[2]);
                    } catch(e){
                        this.error("element not found");
                    }
                    break;
                case "select":
                        this.statusChange(`Selecting input ${seq[1]} with "${seq[2]}"`);
                        try{
                            await crawler.page().select(seq[1], seq[2]);
                        } catch(e){
                            this.error("element not found");
                        }
                        break;
                case "click":
                    this.statusChange(`Click ${seq[1]}`);
                    try{
                        await crawler.page().click(seq[1]);
                    } catch(e){
                        this.error("element not found");
                    }
                    await crawler.waitForRequestsCompletion();
                    break;
                case "clickToNavigate":
                    this.statusChange(`Click to navigate ${seq[1]} ${seq[2] || ''}`);
                    try{
                        await crawler.clickToNavigate(seq[1], seq[2], seq[3]);
                    } catch(err){
                        this.error(err);
                    }
                    break;
                case "navigate":
                    this.statusChange(`Navigate ${seq[1]}`);
                    try{
                        await crawler.navigate(seq[1]);
                    } catch(err){
                        this.error(err);
                    }
                    break;
                case "setTarget":
                    this.statusChange(`Set Target element ${seq[1]}`);
                    this.result.targetElement = seq[1];
                    break;
                default:
                    this.error("action not found");
            }
            this.seqline++;
        }
        this.statusChange(`Sequence finished: ${sequenceType}`);
    }

    error(message){
        if(this.seqline){
            message = "action " + this.seqline + ": " + message;
        }
        throw message;
    }
    
};