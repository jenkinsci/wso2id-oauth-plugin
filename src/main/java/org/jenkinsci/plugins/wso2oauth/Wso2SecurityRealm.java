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
import jenkins.model.Jenkins;
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
import java.net.Proxy;
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
        parameters.add(new BasicNameValuePair("redirect_uri", this.getJenkinsUrl(request)+ "securityRealm/finishLogin" ));
        parameters.add(new BasicNameValuePair("response_type", "code"));
        parameters.add(new BasicNameValuePair("client_id", clientID));

        return new HttpRedirect(this.getWso2WebUri() + "/oauth2/authorize?" + URLEncodedUtils.format(parameters, StandardCharsets.UTF_8));
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
