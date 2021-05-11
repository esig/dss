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

/**
 * This class is a DTO which contains proxy properties for HTTP or HTTPS
 * 
 */
public class ProxyProperties {

	/** The host to use */
	private String host;
	/** The port to use */
	private int port;
	/** The user to use */
	private String user;
	/** The password to use */
	private String password;
	/** Allows multiple urls (separator ',', ';' or ' ') */
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
	 * Returns the excluded hosts (can be separated by ',', ';' or ' ')
	 * 
	 * @return the excluded hosts
	 */
	public String getExcludedHosts() {
		return excludedHosts;
	}

	/**
	 * Set the excluded hosts (can be separated by ',', ';' or ' ')
	 * 
	 * @param excludedHosts
	 *            the excluded hosts (can be separated by ',', ';' or ' ')
	 */
	public void setExcludedHosts(String excludedHosts) {
		this.excludedHosts = excludedHosts;
	}

}
