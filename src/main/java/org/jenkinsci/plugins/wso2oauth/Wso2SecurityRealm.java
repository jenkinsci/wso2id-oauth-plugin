package org.jenkinsci.plugins.wso2oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.model.User;
import jenkins.model.Jenkins;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.kohsuke.stapler.*;
import org.springframework.security.web.util.UrlUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by jylzobei on 28/03/17.
 */
public class Wso2SecurityRealm extends SecurityRealm {

    public static final String DEFAULT_COMMENCE_LOGIN_URL = "securityRealm/commenceLogin";
    public static final String DEFAULT_FINISH_LOGIN_URL = "securityRealm/finishLogin";
    private static final String REFERER_ATTRIBUTE = Wso2SecurityRealm.class.getName() + ".referer";

    private String wso2WebUri;
    private String clientID;
    private String clientSecret;

    @DataBoundConstructor
    public Wso2SecurityRealm(String wso2WebUri, String authorizeUrl, String clientID, String clientSecret) {
        this.wso2WebUri =  Util.fixEmptyAndTrim(wso2WebUri);
        this.clientID = clientID;
        this.clientSecret = clientSecret;
    }

    @Override
    public String getLoginUrl() {
        return DEFAULT_COMMENCE_LOGIN_URL;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents();
    }

    public String getWso2WebUri() {
        return wso2WebUri;
    }

    public String getClientID() {
        return clientID;
    }


    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Get the root Jenkins URL configured in global settings.
     * @return Jenkins URL
     */
    public static String getJenkinsUrl() {
        return Jenkins.getInstance().getRootUrl();
    }

    /**
     * Get the root Jenkins URL configured in global settings, or construct it
     * from the current HTTP request.
     * @param req current HTTP request
     * @return Jenkins URL
     */
    public static String getJenkinsUrl(HttpServletRequest req) {
        String jenkinsUrl = getJenkinsUrl();
        if (jenkinsUrl == null && req != null) {
            jenkinsUrl = UrlUtils.buildFullRequestUrl(req.getScheme(), req.getServerName(), req.getServerPort(), req.getContextPath(), null) + "/";
        }
        return jenkinsUrl;
    }

    private String buildRedirectUrl(StaplerRequest request) throws MalformedURLException {
        return this.getJenkinsUrl(request)+ DEFAULT_FINISH_LOGIN_URL;
    }

    /**
     * The login process starts from here, using the CasAuthenticationEntryPoint
     * defined in the CasSecurityRealm.groovy application context.
     * @param request request
     * @param referer String
     * @throws IOException
     */
    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {
        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

        // 2. Requesting authorization :
        // http://doc.gitlab.com/ce/api/oauth2.html

        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("redirect_uri", this.buildRedirectUrl(request)));
        parameters.add(new BasicNameValuePair("response_type", "code"));
        parameters.add(new BasicNameValuePair("client_id", clientID));

        return new HttpRedirect(this.getWso2WebUri() + "/oauth2/authorize?" + URLEncodedUtils.format(parameters, StandardCharsets.UTF_8));
    }

    /**
     * This is where the user comes back to at the end of the OpenID redirect
     * ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("code");

        if (StringUtils.isBlank(code)) {
            Log.info("doFinishLogin: missing code.");
            return HttpResponses.redirectToContextRoot();
        }

        String accessToken = getAccessToken(request, code);

        if (StringUtils.isNotBlank(accessToken)) {
            // only set the access token if it exists.
            Wso2AuthenticationToken auth = new Wso2AuthenticationToken(accessToken, this.getWso2WebUri());
            SecurityContextHolder.getContext().setAuthentication(auth);
        } else {
            Log.info("WSO2 did not return an access token.");
        }

        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        }
        return HttpResponses.redirectToContextRoot(); // referer should be
        // always there, but be
        // defensive
    }

    private String getAccessToken(StaplerRequest request, String code) throws IOException {
        HttpPost httpPost = new HttpPost(this.wso2WebUri + "/oauth2/token");
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("client_id", clientID));
        parameters.add(new BasicNameValuePair("client_secret", clientSecret));
        parameters.add(new BasicNameValuePair("code", code));
        parameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
        parameters.add(new BasicNameValuePair("redirect_uri", this.buildRedirectUrl(request)));
        httpPost.setEntity(new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8));

        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpHost proxy = getProxy(httpPost);
        if (proxy != null) {
            RequestConfig config = RequestConfig.custom()
                    .setProxy(proxy)
                    .build();
            httpPost.setConfig(config);
        }

        org.apache.http.HttpResponse response = httpclient.execute(httpPost);

        HttpEntity entity = response.getEntity();

        String content = EntityUtils.toString(entity);

        // When HttpClient instance is no longer needed,
        // shut down the connection manager to ensure
        // immediate deallocation of all system resources
        httpclient.close();

        return extractToken(content);
    }

    /**
     * Returns the proxy to be used when connecting to the given URI.
     */
    private HttpHost getProxy(HttpUriRequest method) throws URIException {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            return null; // defensive check
        }
        ProxyConfiguration proxy = jenkins.proxy;
        if (proxy == null)
        {
            return null; // defensive check
        }

        Proxy p = proxy.createProxy(method.getURI().getHost());
        switch (p.type()) {
            case DIRECT:
                return null; // no proxy
            case HTTP:
                InetSocketAddress sa = (InetSocketAddress) p.address();
                return new HttpHost(sa.getHostName(), sa.getPort());
            case SOCKS:
            default:
                return null; // not supported yet
        }
    }

    private String extractToken(String content) {

        ObjectMapper mapper = new ObjectMapper();
        String access_token = null;
        try {
            JsonNode node = mapper.readValue(content, JsonNode.class);
            JsonNode accessTokenNode = node.get("access_token");
            if(accessTokenNode != null){
                access_token = accessTokenNode.asText();
            }

        } catch (IOException e) {
            Log.error(e.getMessage(), e);
        }
        return access_token;
    }


    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public Descriptor<SecurityRealm> getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link Wso2SecurityRealm}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See {@code src/main/resources/hudson/plugins/hello_world/Wso2SecurityRealm/*.jelly}
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        /**
         * In order to load the persisted global configuration, you have to
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            load();
        }

        /**
         * Performs on-the-fly validation of the form field 'name'.
         *
         * @param value
         *      This parameter receives the value that the user has typed.
         * @return
         *      Indicates the outcome of the validation. This is sent to the browser.
         *      <p>
         *      Note that returning {@link FormValidation#error(String)} does not
         *      prevent the form from being saved. It just means that a message
         *      will be displayed to the user.
         */
        public FormValidation doCheckWso2WebUri(@QueryParameter String value)
        {
            if (value.length() == 0)
                return FormValidation.error("Please set a Wso2WebUri");
            return FormValidation.ok();
        }

        public FormValidation doCheckClientID(@QueryParameter String value)
        {
            if (value.length() == 0)
                return FormValidation.error("Please set a clientID");
            return FormValidation.ok();
        }
        public FormValidation doCheckClientSecret(@QueryParameter String value)
        {
            if (value.length() == 0)
                return FormValidation.error("Please set a clientSecret");
            return FormValidation.ok();
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "WSO2 Oauth Plugin";
        }
    }
}
