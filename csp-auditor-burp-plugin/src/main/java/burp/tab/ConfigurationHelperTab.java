package burp.tab;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITab;
import ca.gosecure.cspauditor.gui.generator.CspGeneratorPanel;
import ca.gosecure.cspauditor.gui.generator.CspGeneratorPanelController;

import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import ca.gosecure.cspauditor.model.generator.DetectInlineJavascript;
import com.esotericsoftware.minlog.Log;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;

/**
 * Tab that contains three parts :
 * - Configuration
 * - External Resources
 * - Inline Scripts
 */
public class ConfigurationHelperTab implements ITab, CspGeneratorPanelController {

    private CspGeneratorPanel panel;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private RequestResponsePanel resourceReqRespTab;
    private RequestResponsePanel inlineReqRespTab;
    private RequestResponsePanel reportReqRespTab;

    public ConfigurationHelperTab(final IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        panel = new CspGeneratorPanel(this);
        panel.init();
        resourceReqRespTab = new RequestResponsePanel(callbacks);
        panel.setResourceItem(resourceReqRespTab);
        inlineReqRespTab = new RequestResponsePanel(callbacks);
        panel.setInlineItem(inlineReqRespTab);
        reportReqRespTab = new RequestResponsePanel(callbacks);
        panel.setReportItem(reportReqRespTab);
    }

    @Override
    public String getTabCaption() {
        return "CSP";
    }

    @Override
    public Component getUiComponent() {
        return panel.getRootPanel();
    }

    @Override
    public void analyzeDomain(String domain) {

        IHttpRequestResponse[] reqResponses = callbacks.getProxyHistory();

        ContentSecurityPolicy csp = new ContentSecurityPolicy("CSP");
        csp.addDirectiveValue("default-src","'self'");
        try {
            URL domainSelected = new URL(domain);
            Log.debug("Analysing domain "+domain);
            panel.clearResources();
            panel.clearInlineScript();
            panel.clearReports();
            int id = 0;
            for (IHttpRequestResponse reqResp : reqResponses) {
                id++;
                Log.debug("Request "+id);
                IRequestInfo reqInfo = helpers.analyzeRequest(reqResp.getHttpService(), reqResp.getRequest());
                if (reqResp.getResponse() == null) continue;
                IResponseInfo respInfo = helpers.analyzeResponse(reqResp.getResponse());

                String mimeType = respInfo.getInferredMimeType().toUpperCase(); //Uppercase is applied because to make the content-type uniform

                URL urlRequested = reqInfo.getUrl();
                String urlString = getUrl(reqInfo);
                String protoAndHost = urlRequested.getProtocol() + "://" + urlRequested.getHost();

                boolean isRequestToDomain = protoAndHost.equals(domain);

                //Finding inline script

                String host = getHeader("host", reqInfo.getHeaders());
                if (isRequestToDomain) {//Same-Origin
                    if (mimeType.equals("HTML")) {
                        List<String> problemInline = DetectInlineJavascript.getInstance().findInlineJs(new String(reqResp.getResponse()));

                        for (String line : problemInline)
                            panel.addInlineScript(String.valueOf(id), urlString, line);
                    }
                }


                //Finding external resources

                if (!isRequestToDomain) {//Different-Origin

                    String referrer = getHeader("referer", reqInfo.getHeaders());
                    if (referrer.startsWith("http://") || referrer.startsWith("https://")) { //Just to make sure the URL will be parsable
                        URL referrerUrl = new URL(referrer);
                        if (domainSelected.getHost().equals(referrerUrl.getHost())) {
                            panel.addResource(String.valueOf(id), urlString, mimeType);
                            mimeTypeToDirective(mimeType, protoAndHost, csp);

                        }
                    }
                }


                byte[] completeRequest = reqResp.getRequest();
                int startOffset = reqInfo.getBodyOffset();
                if(completeRequest.length - startOffset != 0) { //Skip GET request
                    byte[] part = Arrays.copyOfRange(completeRequest, startOffset, completeRequest.length);
                    String body = new String(part);
                    if (body.contains("{\"csp-report\":{")) {
                        try {
                            JSONObject rootJson = new JSONObject(body);
                            String documentUri       = rootJson.getJSONObject("csp-report").getString("document-uri");
                            String originalPolicy    = rootJson.getJSONObject("csp-report").getString("original-policy");
                            // chrome sends just the directive. firefox sends directive + sources. e.g. script-src https://domain.com ...
                            String violatedDirective = rootJson.getJSONObject("csp-report").getString("violated-directive").split(" ")[0];
                            String blockedUri;

                            if (violatedDirective.equalsIgnoreCase("frame-ancestors")) {
                                // the report's blocked-uri is the page that got framed, not the one that needs to be added to the policy.
                                blockedUri = rootJson.getJSONObject("csp-report").getString("referrer").split(" ")[0];
                                if (blockedUri.isEmpty())
                                    continue; // browsers won't always send referrer, in which case we can't use the report.
                            }
                            else{
                                blockedUri = rootJson.getJSONObject("csp-report").getString("blocked-uri");
                            }

                            String newSrc = blockedUri;
                            try {
                                URL url = new URL(blockedUri);
                                String port = url.getPort() == -1 ? "" : ":" + Integer.toString(url.getPort());
                                newSrc = url.getProtocol() + "://" + url.getHost() + port;
                            }
                            catch (MalformedURLException e) {
                                if (blockedUri.equalsIgnoreCase("inline")
                                        || blockedUri .equalsIgnoreCase("eval")){
                                    newSrc = "'unsafe-" + blockedUri + "'";
                                }
                                else if (blockedUri.equalsIgnoreCase("data") || blockedUri.equalsIgnoreCase("blob")){
                                    newSrc = blockedUri + ":";
                                }
                                else {
                                    Log.error("Invalid blocked uri", blockedUri);
                                }
                            }

                            if (newSrc.equalsIgnoreCase(domain)) {
                                newSrc = "'self'";
                            }

                            csp.addDirectiveValue(violatedDirective, newSrc);
                            panel.addReport(String.valueOf(id), blockedUri, documentUri, originalPolicy, violatedDirective);
                        }
                        catch (JSONException e){ //Invalid csp-report
                            Log.error("Invalid CSP report at "+urlString);
                        }
                    }
                }

            }
        } catch (Exception e) {
            Log.error(e.getMessage(),e);
        }


        csp.addDirectiveValue("report-uri", "/change-this-uri/");
        displayConfiguration(csp);
        Log.debug("Done analyzing "+domain);
    }

    private void mimeTypeToDirective(String mimeType,String host,ContentSecurityPolicy csp) {

        String directive = null;
        switch (mimeType) {
            //case "HTML": return "frame-ancestors";
//            case "APPLET":
//            case "JAR":
//                return "object-src";
            case "CSS":
                directive = "style-src";
                break;
            case "PNG":
            case "JPG":
            case "JPEG":
            case "GIF":
                directive = "img-src";
                break;
            case "SCRIPT":
                directive = "script-src";
                break;
            case "FONT":
                directive = "font-src";
                break;
            case "WAV":
            case "MP3":
            case "MPG":
            case "MPEG":
            case "AVI":
                directive = "media-src";
                break;
            default:
                Log.debug("Unknown MimeType "+mimeType);
        }

        if(directive != null) {
            csp.addDirectiveValue(directive, host);
            if(host.equals("https://fonts.googleapis.com")) {
                csp.addDirectiveValue("style-src", "https://fonts.gstatic.com");
            }
        }

    }

    @Override
    public void refreshDomains() {

        Log.debug("Refreshing the domain list");
        DomainRefreshTask task = new DomainRefreshTask();
        task.execute();
    }

    protected class DomainRefreshTask extends SwingWorker<SortedSet<String>, String> {

        SortedSet<String> hosts = new TreeSet<>();

        @Override
        public SortedSet<String> doInBackground() {
            IHttpRequestResponse[] reqResponses = callbacks.getProxyHistory();
            hosts = new TreeSet<>();
            for (IHttpRequestResponse reqResp : reqResponses) {
                if ( !isCancelled() ) {
                    IRequestInfo reqInfo = helpers.analyzeRequest(reqResp.getHttpService(), reqResp.getRequest());
                    String domain = reqInfo.getUrl().getProtocol() + "://" + reqInfo.getUrl().getHost();
                    hosts.add(domain);
                    publish(domain);
                }
            }

            return hosts;
        }

        @Override
        public void process(List<String> domains) {
            for (String domain : domains) {
                panel.addDomain(domain);
            }
        }

    }

    @Override
    public void selectResource(String url) {
        displayReqResp(url, resourceReqRespTab);
    }

    @Override
    public void selectInline(String id) {
        inlineReqRespTab.selectResponse();
        displayReqResp(id, inlineReqRespTab);
    }

    @Override
    public void selectReport(String id) {
        displayReqResp(id, reportReqRespTab);
    }

    private void displayReqResp(String id, RequestResponsePanel tabbedPane) {
        //IHttpRequestResponse[] reqResponses = callbacks.getSiteMap(url);
        try {
            Integer requestId = Integer.parseInt(id);

            IHttpRequestResponse reqResp = callbacks.getProxyHistory()[requestId-1];
            if (reqResp != null) {

                tabbedPane.editorRequest.setMessage(reqResp.getRequest(), true);
                if (reqResp.getResponse() != null) tabbedPane.editorResponse.setMessage(reqResp.getResponse(), false);

            } else {
                Log.error("Oups request not found.");
            }
        }
        catch (NumberFormatException | IndexOutOfBoundsException e) {

        }

    }

    private void displayConfiguration(ContentSecurityPolicy policy) {

        IMessageEditor msg = callbacks.createMessageEditor(null, true);

        StringBuilder str = new StringBuilder();
        str.append("Content-Security-Policy: ");
        str.append(policy.toHeaderString());
        str.append("\n\n");

        msg.setMessage(str.toString().getBytes(), false);

        panel.setConfiguration(msg.getComponent());
    }

    private String getUrl(IRequestInfo reqInfo) {
        String url = reqInfo.getUrl().toString();

        try {//BUG: BurpSuite does not support default port being specified to getSiteMap() API
            URL urlTest = new URL(url); // Test if for port to remove from url
            if (urlTest.getDefaultPort() == urlTest.getPort()) {
                url = urlTest.getProtocol() + "://" + urlTest.getHost() + urlTest.getPath();
                if (urlTest.getQuery() != null) {
                    url += "?" + urlTest.getQuery();
                }
            }
        } catch (MalformedURLException e) {
        }

        return url;
    }

    private String getHeader(String name, List<String> headers) {
        for (String h : headers) {
            String[] parts = h.split(":", 2);
            String headerName = parts[0].trim();
            if (headerName.equalsIgnoreCase(name) && parts.length > 1) {
                return parts[1].trim();
            }
        }
        return "";
    }
}
