package org.jenkinsci.plugins;

import hudson.security.UserMayOrMayNotExistException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

/**
 * Created by jylzobei on 30/03/17.
 */
public class Wso2IdUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        Wso2IdAuthenticationToken authToken;
        if (SecurityContextHolder.getContext().getAuthentication() instanceof Wso2IdAuthenticationToken) {
            authToken = (Wso2IdAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        } else {
            throw new UserMayOrMayNotExistException("Could not get auth token.");
        }

        try {
            Wso2IdOAuthUserDetails userDetails = new Wso2IdOAuthUserDetails(username, authToken.getAuthorities());
            if (userDetails == null) {
                throw new UsernameNotFoundException("Unknown user: " + username);
            }

            return userDetails;
        } catch (Error e) {
            throw new DataRetrievalFailureException("loadUserByUsername (username=" + username + ")", e);
        }
    }
}
