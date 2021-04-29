package com.tracelink.appsec.watchtower.core.auth.model;

import javax.validation.constraints.NotBlank;

/**
 * Data object for new user registration
 *
 * @author csmith
 */
public class UserRegistrationForm {
    private String username;
    @NotBlank(message = "Please provide a password")
    private String password;
    private String passwordConfirmation;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPasswordConfirmation() {
        return passwordConfirmation;
    }

    public void setPasswordConfirmation(String passwordConfirmation) {
        this.passwordConfirmation = passwordConfirmation;
    }
}
