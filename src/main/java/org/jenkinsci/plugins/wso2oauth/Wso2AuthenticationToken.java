package org.jenkinsci.plugins.wso2oauth;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

import java.io.IOException;
import java.io.Serializable;

/**
 * Created by jylzobei on 29/03/17.
 */
public class Wso2AuthenticationToken extends AbstractAuthenticationToken implements Serializable {

    private final String accessToken;
    private final String wso2WebUri;
   private final Wso2User wso2User;
    private final Wso2Client wso2Client;

    public Wso2AuthenticationToken(String accessToken, String wso2WebUri) throws IOException {
        super(new GrantedAuthority[] {});
        this.wso2Client = new Wso2Client();
        this.accessToken = accessToken;
        this.wso2WebUri = wso2WebUri;
        this.wso2User = this.getUserDetails();

    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.wso2User.getName();
    }

    public Wso2User getWso2User() {
        return wso2User;
    }

    private Wso2User getUserDetails() throws IOException {
       return wso2Client.getUser(this.wso2WebUri + "/oauth2/userinfo?schema=openid", accessToken);
    }

}
