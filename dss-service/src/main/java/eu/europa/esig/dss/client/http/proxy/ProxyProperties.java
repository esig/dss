package eu.europa.esig.dss.client.http.proxy;

/**
 * This class is a DTO which contains proxy properties for HTTP or HTTPS
 * 
 */
public class ProxyProperties {

	/* The host to use */
	private String host;
	/* The port to use */
	private int port;
	/* The user to use */
	private String user;
	/* The password to use */
	private String password;
	/* Allows multiple urls (separator ',', ';' or ' ') */
	private String excludedHosts;

	/**
	 * Returns the proxy host to use
	 * 
	 * @return the proxy host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * Set the proxy host
	 * 
	 * @param host
	 *            the host to use
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * Returns the port to use
	 * 
	 * @return the proxy port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Set the proxy port
	 * 
	 * @param port
	 *            the port to use
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * Returns the user to use
	 * 
	 * @return the proxy user
	 */
	public String getUser() {
		return user;
	}

	/**
	 * Set the proxy user
	 * 
	 * @param user
	 *            the user to use
	 */
	public void setUser(String user) {
		this.user = user;
	}

	/**
	 * Returns the password to use
	 * 
	 * @return the proxy password
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * Set the proxy password
	 * 
	 * @param password
	 *            the password to use
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * Returns the excluded hosts (can be seperated by ',', ';' or ' ')
	 * 
	 * @return the excluded hosts
	 */
	public String getExcludedHosts() {
		return excludedHosts;
	}

	/**
	 * Set the excluded hosts (can be seperated by ',', ';' or ' ')
	 * 
	 * @param excludedHosts
	 *            the excluded hosts (can be seperated by ',', ';' or ' ')
	 */
	public void setExcludedHosts(String excludedHosts) {
		this.excludedHosts = excludedHosts;
	}

}
