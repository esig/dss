package eu.europa.esig.dss.service.http.commons;

/**
 * This object defines a configuration details for HTTP connection to the given host
 *
 */
public class HostConnection {

    /** The name of the remote host */
    private String host;

    /** The port of the host */
    private int port = -1;

    /** Authentication scheme */
    private String scheme;

    /** The realm of the host */
    private String realm;

    /**
     * Empty constructor
     */
    public HostConnection() {
    }

    /**
     * Constructor with host name and port
     *
     * @param host {@link String}
     * @param port integer
     */
    public HostConnection(String host, int port) {
        this(host, port, null);
    }

    /**
     * Constructor with host name, port and authentication scheme
     *
     * @param host {@link String}
     * @param port integer
     * @param scheme {@link String}
     */
    public HostConnection(String host, int port, String scheme) {
        this(host, port, scheme, null);
    }

    /**
     * Complete constructor
     *
     * @param host {@link String}
     * @param port integer
     * @param scheme {@link String}
     * @param realm {@link String}
     */
    public HostConnection(String host, int port, String scheme, String realm) {
        this.host = host;
        this.port = port;
        this.scheme = scheme;
        this.realm = realm;
    }

    /**
     * Gets the host name
     *
     * @return {@link String}
     */
    public String getHost() {
        return host;
    }

    /**
     * Sets the host name
     *
     * @param host {@link String}
     */
    public void setHost(String host) {
        this.host = host;
    }

    /**
     * Gets the host port
     *
     * @return integer
     */
    public int getPort() {
        return port;
    }

    /**
     * Sets the host port
     *
     * Default : -1 (any port)
     *
     * @param port integer value
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Gets the authentication scheme
     *
     * @return {@link String}
     */
    public String getScheme() {
        return scheme;
    }

    /**
     * Sets the authentication scheme
     *
     * @param scheme {@link String}
     */
    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    /**
     * Gets the realm
     *
     * @return {@link String}
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Sets the realm
     *
     * @param realm {@link String}
     */
    public void setRealm(String realm) {
        this.realm = realm;
    }

}
