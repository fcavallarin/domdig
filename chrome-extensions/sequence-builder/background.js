// Empty service_worker used as proxy between node and the UI (devtools panel)

const messageQueue = [];
let lastPingTime = 0;
const sendMessage = (message) => {
    messageQueue.push(message);
};


setTimeout(async function loop(){
    try{
        if(messageQueue.length === 0 && (new Date()).getTime() - lastPingTime > 2000){
            // Keep the worker active
            try{
                await chrome.runtime.sendMessage({ping: 1});
            }catch(e){}
            lastPingTime = (new Date()).getTime();
        }
        for(let i = messageQueue.length - 1; i >= 0; i--){
            try{
                await chrome.runtime.sendMessage({body: messageQueue[i]});
            }catch(e){
                // Failed to send message
                break;
            }
            messageQueue.splice(i, 1);
        }
    }catch(e){
        console.error(`Exception from Service Worker: ${e}`)
    }
    setTimeout(loop, 200);
}, 200);