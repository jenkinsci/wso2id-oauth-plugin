package org.jenkinsci.plugins;

/**
 * Created by jylzobei on 29/03/17.
 */
public class Wso2User {

    private final String name;
    private final String email;
    private final String username;

    public Wso2User(String username, String name, String email) {
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
