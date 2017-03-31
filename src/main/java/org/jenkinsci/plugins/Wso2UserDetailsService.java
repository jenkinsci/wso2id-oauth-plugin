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
public class Wso2UserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        Wso2AuthenticationToken authToken;
        if (SecurityContextHolder.getContext().getAuthentication() instanceof Wso2AuthenticationToken) {
            authToken = (Wso2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        } else {
            throw new UserMayOrMayNotExistException("Could not get auth token.");
        }

        try {
            Wso2OAuthUserDetails userDetails = new Wso2OAuthUserDetails(username, authToken.getAuthorities());
            if (userDetails == null) {
                throw new UsernameNotFoundException("Unknown user: " + username);
            }

            return userDetails;
        } catch (Error e) {
            throw new DataRetrievalFailureException("loadUserByUsername (username=" + username + ")", e);
        }
    }
}
