package eu.europa.esig.dss.service.http.commons;

/**
 * This class represents a user credentials object used to authenticate to a remote host
 *
 */
public class UserCredentials {

    /** Identifies user's login name or username */
    private String username;

    /** The password authentication string */
    private String password;

    /**
     * Empty constructor
     */
    public UserCredentials() {
    }

    /**
     * Default constructor
     *
     * @param username {@link String}
     * @param password {@link String}
     */
    public UserCredentials(String username, String password) {
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
    public String getPassword() {
        return password;
    }

    /**
     * Sets the password
     *
     * @param password {@link String}
     */
    public void setPassword(String password) {
        this.password = password;
    }

}
