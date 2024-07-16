exports.InteractiveUI = class {
    constructor(domdig){
        this.domdig = domdig;
        this.isSelectingElement = false;
        this.isLoggingIn = false;
        this.customUI = {
            extensionPath: __dirname + '/chrome-extensions/interactive',
            UIMethods: UI => {
                UI.scanElement = async () => {
                    if(this.isSelectingElement){
                        return;
                    }
                    this.isSelectingElement = true;
                    const el = await UI.utils.selectElement();
                    this.isSelectingElement = false;
                    UI.dispatch(`scanElement`, {element: el.selector});
                };
                UI.start = () => {
                    UI.dispatch("start");
                }
                UI.login = () => {
                    UI.dispatch("login");
                }
            },
            events: {
                scanElement: async (e, crawler) => {
                    this.domdig.targetElement = e.params.element;
                    await this.domdig.startScan();
                },
                start: async (e, crawler) => {
                    await this.domdig.startScan();
                },
                login: async (e, crawler) => {
                    if(this.isLoggingIn){
                        crawler.sendToUI("Login on the newly opened page")
                        return;
                    }
                    this.isLoggingIn = true;
                    const p = await crawler.newDetachedPage();
                    await p.evaluate(() => document.write("<h2>Close this page when done</h2>"));
                    p.on("close", async () => {
                        this.isLoggingIn = false;
                        await crawler.reload();
                    })
                },
            }
        }
    }
}
