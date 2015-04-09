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
 * Thrown when using bad password
 *
 *
 */

public class DSSBadPasswordException extends RuntimeException {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/esig/dss/i18n");

	private MSG key;

	/**
	 * Supported messages
	 */
	public enum MSG {
		PKCS11_BAD_PASSWORD, PKCS12_BAD_PASSWORD, JAVA_KEYSTORE_BAD_PASSWORD
	}

	/**
	 * The default constructor for DSSBadPasswordException.
	 *
	 * @param message
	 */
	public DSSBadPasswordException(MSG message) {
		init(message);
	}

	public DSSBadPasswordException(MSG message, Throwable cause) {
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
