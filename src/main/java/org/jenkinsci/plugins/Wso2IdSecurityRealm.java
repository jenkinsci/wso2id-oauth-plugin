package org.jenkinsci.plugins;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.model.User;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.jfree.util.Log;
import org.kohsuke.stapler.*;
import org.springframework.security.web.util.UrlUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by jylzobei on 28/03/17.
 */
public class Wso2IdSecurityRealm extends SecurityRealm {

    public static final String DEFAULT_COMMENCE_LOGIN_URL = "securityRealm/commenceLogin";
    public static final String DEFAULT_FINISH_LOGIN_URL = "securityRealm/finishLogin";
    private static final String REFERER_ATTRIBUTE = Wso2IdSecurityRealm.class.getName() + ".referer";

    private String wso2idWebUri;
    private String clientID;
    private String clientSecret;

    @DataBoundConstructor
    public Wso2IdSecurityRealm(String wso2idWebUri, String authorizeUrl, String clientID, String clientSecret) {
        this.wso2idWebUri =  Util.fixEmptyAndTrim(wso2idWebUri);
        this.clientID = clientID;
        this.clientSecret = clientSecret;
    }

    @Override
    public String getLoginUrl() {
        return DEFAULT_COMMENCE_LOGIN_URL;
    }

    public String getWso2idWebUri() {
        return wso2idWebUri;
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
        Jenkins jenkins = Jenkins.getInstance();
        if(jenkins == null) {
            return null;
        }
        return jenkins.getRootUrl();
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

        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("redirect_uri", this.buildRedirectUrl(request)));
        parameters.add(new BasicNameValuePair("response_type", "code"));
        parameters.add(new BasicNameValuePair("client_id", clientID));
        parameters.add(new BasicNameValuePair("scope", "openid"));

        return new HttpRedirect(this.getWso2idWebUri() + "/oauth2/authorize?" + URLEncodedUtils.format(parameters, StandardCharsets.UTF_8));
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
            Wso2IdAuthenticationToken auth = new Wso2IdAuthenticationToken(accessToken, this.getWso2idWebUri());
            SecurityContextHolder.getContext().setAuthentication(auth);

            Wso2IdUser wso2User = auth.getWso2User();
            User user = User.current();
            if (user != null) {
                user.setFullName(wso2User.getName());
                // Set email from wso2is only if empty
                if (!user.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
                    user.addProperty(new Mailer.UserProperty(wso2User.getEmail()));
                }
            }
            SecurityListener.fireAuthenticated(new Wso2IdOAuthUserDetails(wso2User.getUsername(), auth.getAuthorities()));
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
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("client_id", clientID));
        parameters.add(new BasicNameValuePair("client_secret", clientSecret));
        parameters.add(new BasicNameValuePair("code", code));
        parameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
        parameters.add(new BasicNameValuePair("redirect_uri", this.buildRedirectUrl(request)));
//        parameters.add(new BasicNameValuePair("scope", "openid"));
        Wso2IdClient wso2Client = new Wso2IdClient();
        String content = wso2Client.post(this.wso2idWebUri + "/oauth2/token", parameters);
        return extractToken(content);
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

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {

            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof Wso2IdAuthenticationToken) {
                    return authentication;
                }
                if (authentication instanceof UsernamePasswordAuthenticationToken) {
                    try {
                        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
                        Wso2IdAuthenticationToken wso2AuthenticationToken = new Wso2IdAuthenticationToken(token.getCredentials().toString(), getWso2idWebUri());
                        SecurityContextHolder.getContext().setAuthentication(wso2AuthenticationToken);
                        return wso2AuthenticationToken;
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        }, new Wso2IdUserDetailsService());
    }


    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public Descriptor<SecurityRealm> getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link Wso2IdSecurityRealm}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See {@code src/main/resources/hudson/plugins/hello_world/Wso2IdSecurityRealm/*.jelly}
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
