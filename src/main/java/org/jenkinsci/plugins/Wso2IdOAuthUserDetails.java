package org.jenkinsci.plugins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

/**
 * Created by jylzobei on 30/03/17.
 */
public class Wso2IdOAuthUserDetails extends User implements UserDetails {

    public Wso2IdOAuthUserDetails(String username, GrantedAuthority[] authorities) {
        super(username, "", true, true, true, true, authorities);

    }

}
