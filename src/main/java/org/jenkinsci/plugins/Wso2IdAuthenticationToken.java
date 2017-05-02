package org.jenkinsci.plugins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

import java.io.IOException;
import java.io.Serializable;

/**
 * Created by jylzobei on 29/03/17.
 */
public class Wso2IdAuthenticationToken extends AbstractAuthenticationToken implements Serializable {

    private final String accessToken;
    private final String wso2WebUri;
    private final Wso2IdUser wso2User;
    private final transient Wso2IdClient wso2Client;

    public Wso2IdAuthenticationToken(String accessToken, String wso2WebUri) throws IOException {
        super(new GrantedAuthority[] {});
        this.wso2Client = new Wso2IdClient();
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

    public Wso2IdUser getWso2User() {
        return wso2User;
    }

    private Wso2IdUser getUserDetails() throws IOException {
       return wso2Client.getUser(this.wso2WebUri + "/oauth2/userinfo?schema=openid", accessToken);
    }

}
