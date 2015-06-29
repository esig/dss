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
 * Keys for retrieving Proxy preferences information
 *
 */
public enum ProxyKey {

	// HTTPS
	HTTPS_HOST("proxy.https.host"),

	HTTPS_PORT("proxy.https.port"),

	HTTPS_USER("proxy.https.user"),

	HTTPS_PASSWORD("proxy.https.password"),

	HTTPS_EXCLUDE("proxy.https.exclude"),

	HTTPS_ENABLED("proxy.https.enabled"),

	//HTTP
	HTTP_HOST("proxy.http.host"),

	HTTP_PORT("proxy.http.port"),

	HTTP_USER("proxy.http.user"),

	HTTP_PASSWORD("proxy.http.password"),

	HTTP_EXCLUDE("proxy.http.exclude"),

	HTTP_ENABLED("proxy.http.enabled");


	private final String keyName;

	ProxyKey(final String keyName) {
		this.keyName = keyName.toLowerCase();
	}

	/**
	 * This method return {@code ProxyKey} corresponding to the string representation of the keyName.<br/>
	 * If there is no corresponding keyName then null is returned.
	 *
	 * @param key
	 * @return
	 */
	public static ProxyKey fromKey(final String key) {

		final String key_ = key.toLowerCase();
		if (ProxyKey.HTTP_ENABLED.keyName.equals(key_)) {
			return ProxyKey.HTTP_ENABLED;
		} else if (ProxyKey.HTTP_HOST.keyName.equals(key_)) {
			return ProxyKey.HTTP_HOST;
		} else if (ProxyKey.HTTP_PASSWORD.keyName.equals(key_)) {
			return ProxyKey.HTTP_PASSWORD;
		} else if (ProxyKey.HTTP_PORT.keyName.equals(key_)) {
			return ProxyKey.HTTP_PORT;
		} else if (ProxyKey.HTTP_USER.keyName.equals(key_)) {
			return ProxyKey.HTTP_USER;
		} else if (ProxyKey.HTTP_EXCLUDE.keyName.equals(key_)) {
			return ProxyKey.HTTP_EXCLUDE;
		} else if (ProxyKey.HTTPS_ENABLED.keyName.equals(key_)) {
			return ProxyKey.HTTPS_ENABLED;
		} else if (ProxyKey.HTTPS_HOST.keyName.equals(key_)) {
			return ProxyKey.HTTPS_HOST;
		} else if (ProxyKey.HTTPS_PASSWORD.keyName.equals(key_)) {
			return ProxyKey.HTTPS_PASSWORD;
		} else if (ProxyKey.HTTPS_PORT.keyName.equals(key_)) {
			return ProxyKey.HTTPS_PORT;
		} else if (ProxyKey.HTTPS_USER.keyName.equals(key_)) {
			return ProxyKey.HTTPS_USER;
		} else if (ProxyKey.HTTPS_EXCLUDE.keyName.equals(key_)) {
			return ProxyKey.HTTPS_EXCLUDE;
		} else {
			return null;
		}
	}

	public String getKeyName() {
		return keyName;
	}

	@Override
	public String toString() {
		return keyName;
	}
}
