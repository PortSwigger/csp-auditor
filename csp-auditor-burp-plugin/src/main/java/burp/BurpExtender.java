package burp;

import burp.scanner.CspHeaderScanner;
import burp.tab.ConfigurationHelperTab;
import com.esotericsoftware.minlog.Log;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

    private  IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private CspHeaderScanner scanner;

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbacks.setExtensionName("CSP Auditor");

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("== CSP Auditor plugin ==");
        stdout.println("This plugin provided a readable view of CSP headers in Response Tab. ");
        stdout.println("It also include Passive scan rules to detect weak CSP configuration.");
        stdout.println(" - Github : https://github.com/GoSecure/csp-auditor");
        stdout.println("");
        stdout.println("== License ==");
        stdout.println("CSP Auditor plugin is release under LGPL.");
        stdout.println("");

        Log.setLogger(new Log.Logger() {
            @Override
            protected void print(String message) {
                callbacks.printOutput(message);
            }
        });
        Log.DEBUG();

        this.callbacks.registerMessageEditorTabFactory(this);

        scanner = new CspHeaderScanner(helpers);
        this.callbacks.registerScannerCheck(scanner);
        this.callbacks.addSuiteTab(new ConfigurationHelperTab(this.callbacks));
    }


    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean b) {
        return new CspTab(this.callbacks, this.helpers, iMessageEditorController);
    }
}
