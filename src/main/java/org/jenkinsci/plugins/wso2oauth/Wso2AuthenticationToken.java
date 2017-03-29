package org.jenkinsci.plugins.wso2oauth;

import org.acegisecurity.providers.AbstractAuthenticationToken;

import java.io.Serializable;

/**
 * Created by jylzobei on 29/03/17.
 */
public class Wso2AuthenticationToken extends AbstractAuthenticationToken implements Serializable {

    private final String accessToken;
    private final String wso2WebUri;

    public Wso2AuthenticationToken(String accessToken, String wso2WebUri) {
        this.accessToken = accessToken;
        this.wso2WebUri = wso2WebUri;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
