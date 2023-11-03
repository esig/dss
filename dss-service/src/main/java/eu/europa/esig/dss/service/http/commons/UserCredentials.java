/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.http.commons;

import java.io.Serializable;

/**
 * This class represents a user credentials object used to authenticate to a remote host
 *
 */
public class UserCredentials implements Serializable {

    private static final long serialVersionUID = -3095450289231987392L;

    /** Identifies user's login name or username */
    private String username;

    /** The authentication password */
    private char[] password;

    /**
     * Empty constructor
     */
    public UserCredentials() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param username {@link String}
     * @param password a char array representing the password string
     */
    public UserCredentials(String username, char[] password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Gets the username
     *
     * @return {@link String}
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username
     *
     * @param username {@link String}
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Gets the password
     *
     * @return {@link String}
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Sets the password
     *
     * @param password {@link String}
     */
    public void setPassword(char[] password) {
        this.password = password;
    }

}
