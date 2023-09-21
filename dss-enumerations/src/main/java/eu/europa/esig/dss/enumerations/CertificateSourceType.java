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
package eu.europa.esig.dss.enumerations;

/**
 * Standard sources for a certificate. Indicates where the certificate comes from.
 */
public enum CertificateSourceType {

	/** Defines a pre-defines trusted source */
	TRUSTED_STORE,

	/** Defines a certificate source populated by a TLValidationJob */
	TRUSTED_LIST,

	/** Certificate source extracted from a signature */
	SIGNATURE,

	/** Certificate source extracted from an OCSP response */
	OCSP_RESPONSE,

	/** Other types of certificate sources */
	OTHER,

	/** The certificate source has been obtained by AIA */
	AIA,

	/** Certificate source extracted from a timestamp */
	TIMESTAMP,

	/** Certificate source extracted from an Evidence record */
	EVIDENCE_RECORD,

	/** The unknown origin of a certificate source */
	UNKNOWN;

	/**
	 * Gets of the certificate source is trusted
	 *
	 * @return TRUE if the certificates in the source are trusted, FALSE otherwise
	 */
	public boolean isTrusted() {
		return TRUSTED_STORE.equals(this) || TRUSTED_LIST.equals(this);
	}

}
