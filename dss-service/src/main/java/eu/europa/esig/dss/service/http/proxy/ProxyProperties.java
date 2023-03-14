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
package eu.europa.esig.dss.service.http.proxy;

import java.io.Serializable;
import java.util.Collection;

/**
 * This class is a DTO which contains proxy properties for HTTP or HTTPS
 * 
 */
public class ProxyProperties implements Serializable {

	private static final long serialVersionUID = 1570253159682776873L;

	/** The host to use */
	private String host;
	/** The port to use */
	private int port;
	/** The user to use */
	private String user;
	/** The password to use */
	private char[] password;
	/** The host connection scheme */
	private String scheme;
	/** Defines a list of hosts (URLs) to be excluded from the proxy configuration */
	private Collection<String> excludedHosts;

	/**
	 * Default constructor with null values
	 */
	public ProxyProperties() {
		// empty
	}

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
	public char[] getPassword() {
		return password;
	}

	/**
	 * Set the proxy password
	 *
	 * @param password
	 *            the password to use
	 */
	public void setPassword(char[] password) {
		this.password = password;
	}

	/**
	 * Gets the host connection scheme
	 *
	 * @return {@link String}
	 */
	public String getScheme() {
		return scheme;
	}

	/**
	 * Sets the host connection scheme (e.g. "http", "https", etc.)
	 *
	 * @param scheme {@link String}
	 */
	public void setScheme(String scheme) {
		this.scheme = scheme;
	}

	/**
	 * Gets a collection of hosts to be excluded
	 *
	 * @return a collection of {@link String}s
	 */
	public Collection<String> getExcludedHosts() {
		return excludedHosts;
	}

	/**
	 * Sets a collection of hosts (URLs) to be excluded from the proxy configuration
	 *
	 * @param excludedHosts
	 *            a collection of hosts URLs to exclude
	 */
	public void setExcludedHosts(Collection<String> excludedHosts) {
		this.excludedHosts = excludedHosts;
	}

}
