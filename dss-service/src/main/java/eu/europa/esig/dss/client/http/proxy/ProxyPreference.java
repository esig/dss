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
package eu.europa.esig.dss.client.http.proxy;

/**
 * Preference information for Proxy
 *
 *
 *
 *
 *
 *
 */
public class ProxyPreference {

	private ProxyKey proxyKey;

	private String value;

	public ProxyPreference() {
	}

	public ProxyPreference(final ProxyKey proxyKey, final String value) {
		this.proxyKey = proxyKey;
		this.value = value;
	}

	/**
	 * @return the key
	 */
	public ProxyKey getProxyKey() {
		return proxyKey;
	}

	/**
	 * @return the value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * @param proxyKey the key to set
	 */
	public void setProxyKey(final ProxyKey proxyKey) {
		this.proxyKey = proxyKey;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(final String value) {
		this.value = value;
	}

	public void setProxyKey(final String proxyKeyString) {

		proxyKey = ProxyKey.fromKey(proxyKeyString);
	}

	@Override
	public String toString() {
		return "ProxyPreference{" +
			  "proxyKey=" + proxyKey +
			  ", value='" + (proxyKey.getKeyName().contains("password") ? "******" : value) + '\'' +
			  '}';
	}
}
