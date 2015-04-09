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
package eu.europa.esig.dss;

import java.util.ResourceBundle;

/**
 * Occurs when a configuration is missing/faulty in the DSS server. Because this exception occurs only when the server
 * is not well configured, it's a RuntimeException.
 *
 *
 */

@SuppressWarnings("serial")
public class DSSConfigurationException extends RuntimeException {

	private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/esig/dss/i18n");

	private MSG key;

	/**
	 * Supported messages
	 */
	public enum MSG {
		CONFIGURE_TSP_SERVER, NOT_PKCS11_LIB
	}

	/**
	 * The default constructor for DSSConfigurationException.
	 */
	public DSSConfigurationException(MSG message) {
		init(message);
	}

	/**
	 * The default constructor for DSSConfigurationException.
	 */
	public DSSConfigurationException(MSG message, Throwable cause) {
		super(cause);
		init(message);
	}

	private void init(MSG message) {
		if (message == null) {
			throw new IllegalArgumentException("Cannot build Exception without a message");
		}
		this.key = message;
	}

	@Override
	public String getLocalizedMessage() {
		return bundle.getString(key.toString());
	}

}
