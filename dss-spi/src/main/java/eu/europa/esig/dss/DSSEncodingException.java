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
 * Occurs when object (X509, CRL, OCSP, ...) is not encoded correctly
 *
 *
 */

@SuppressWarnings("serial")
public class DSSEncodingException extends RuntimeException {

	private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/esig/dss/i18n");

	private MSG key;

	/**
	 * Supported messages
	 */
	public enum MSG {
		CERTIFICATE_CANNOT_BE_READ, OCSP_CANNOT_BE_READ, SIGNATURE_METHOD_ERROR,

		SIGNING_CERTIFICATE_ENCODING, SIGNING_TIME_ENCODING, SIGNATURE_POLICY_ENCODING, COUNTERSIGNATURE_ENCODING,

		SIGNATURE_TIMESTAMP_ENCODING, TIMESTAMP_X1_ENCODING, TIMESTAMP_X2_ENCODING,

		ARCHIVE_TIMESTAMP_ENCODING, CERTIFICATE_REF_ENCODING, CRL_REF_ENCODING,

		OCSP_REF_ENCODING, SIGNATURE_TIMESTAMP_DATA_ENCODING, TIMESTAMP_X1_DATA_ENCODING,

		TIMESTAMP_X2_DATA_ENCODING, ARCHIVE_TIMESTAMP_DATA_ENCODING, CRL_CANNOT_BE_WRITTEN
	}

	/**
	 * The default constructor for DSSEncodingException.
	 *
	 * @param key
	 */
	public DSSEncodingException(MSG key) {
		init(key);
	}

	/**
	 * @param key
	 * @param cause
	 */
	public DSSEncodingException(MSG key, Throwable cause) {
		super(cause);
		init(key);
	}

	private void init(MSG key) {
		if (key == null) {
			throw new IllegalArgumentException("Cannot build Exception without a message");
		}
		this.key = key;
	}

	@Override
	public String getLocalizedMessage() {
		return bundle.getString(key.toString());
	}

}
