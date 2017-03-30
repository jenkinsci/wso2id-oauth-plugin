package org.jenkinsci.plugins.wso2oauth;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

/**
 * Created by jylzobei on 30/03/17.
 */
public class Wso2OAuthUserDetails extends User implements UserDetails {

    public Wso2OAuthUserDetails(String username, GrantedAuthority[] authorities) {
        super(username, "", true, true, true, true, authorities);

    }

}
