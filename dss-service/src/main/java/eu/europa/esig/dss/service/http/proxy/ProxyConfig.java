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
 * This class is a DTO which contains the proxy configuration (HTTP and/or HTTPS)
 */
public class ProxyConfig {

	/** Properties for HTTP Proxy (null if disabled) */
	private ProxyProperties httpProperties;

	/** Properties for HTTPS Proxy (null if disabled) */
	private ProxyProperties httpsProperties;

	/**
	 * Gets HTTP {@code ProxyProperties}
	 *
	 * @return {@link ProxyProperties}
	 */
	public ProxyProperties getHttpProperties() {
		return httpProperties;
	}

	/**
	 * Sets HTTP {@code ProxyProperties}
	 *
	 * @param httpProperties {@link ProxyProperties}
	 */
	public void setHttpProperties(ProxyProperties httpProperties) {
		this.httpProperties = httpProperties;
	}

	/**
	 * Gets HTTPS {@code ProxyProperties}
	 *
	 * @return {@link ProxyProperties}
	 */
	public ProxyProperties getHttpsProperties() {
		return httpsProperties;
	}

	/**
	 * Sets HTTPS {@code ProxyProperties}
	 *
	 * @param httpsProperties {@link ProxyProperties}
	 */
	public void setHttpsProperties(ProxyProperties httpsProperties) {
		this.httpsProperties = httpsProperties;
	}

}
