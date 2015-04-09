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
 * Occurs when something don't respect the ETSI specification
 *
 *
 */

public class DSSNotETSICompliantException extends RuntimeException {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/esig/dss/i18n");

	private MSG key;

	private String more;

	/**
	 * Supported messages
	 */
	public enum MSG {
		TSL_NOT_SIGNED, MORE_THAN_ONE_SIGNATURE, DIFFERENT_SIGNATURE_FORMATS, SIGNATURE_INVALID, NOT_A_VALID_XML,

		UNRECOGNIZED_TAG, UNSUPPORTED_ASSERT,

		XADES_DIGEST_ALG_AND_VALUE_ENCODING,

		ASICS_CADES, NO_SIGNING_TIME, NO_SIGNING_CERTIFICATE
	}

	/**
	 * The default constructor for DSSNotETSICompliantException.
	 *
	 * @param message
	 */
	public DSSNotETSICompliantException(final MSG message) {

		init(message);
	}

	/**
	 * The default constructor for DSSNotETSICompliantException.
	 *
	 * @param message
	 */
	public DSSNotETSICompliantException(final MSG message, final String more) {

		init(message);
		this.more = more;
	}

	public DSSNotETSICompliantException(final MSG message, final Throwable cause) {
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

		final String bundleString = bundle.getString(key.toString());
		return bundleString + ((more != null) ? " / " + more : "");
	}

	@Override
	public String getMessage() {

		return getLocalizedMessage();
	}
}
