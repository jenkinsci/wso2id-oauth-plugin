package org.jenkinsci.plugins;

import java.io.Serializable;

/**
 * Created by jylzobei on 29/03/17.
 */
public class Wso2IdUser implements Serializable {

    private static final long serialVersionUID = -2965499083268052115L;
    private final String name;
    private final String email;
    private final String username;

    public Wso2IdUser(String username, String name, String email) {
        this.username = username;
        this.name = name;
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }
}
