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

public enum RevocationOrigin {

	/**
	 * The revocation data was embedded in the CMS SignedData itself (used in CAdES)
	 */
	CMS_SIGNED_DATA(true),

	/**
	 * The revocation data was embedded in the TimeStampToken.SignedData (used in
	 * CAdES)
	 */
	TIMESTAMP_SIGNED_DATA(true),

	/**
	 * The revocation data was embedded in the signature 'revocation-values'
	 * attribute (used in CAdES and XAdES)
	 */
	REVOCATION_VALUES(true),

	/**
	 * The revocation data was embedded in the signature 'AttributeRevocationValues' attribute (used in XAdES)
	 */
	ATTRIBUTE_REVOCATION_VALUES(true),

	/**
	 * The revocation data was embedded in the signature 'TimeStampValidationData' attribute (used in XAdES)
	 */
	TIMESTAMP_VALIDATION_DATA(true),

	/**
	 * The revocation data was embedded to the contents of DSS PDF dictionary (used in PAdES)
	 */
	DSS_DICTIONARY(true),

	/**
	 * The revocation data was embedded to VRI dictionary (used in PAdES)
	 */
	VRI_DICTIONARY(true),

	/**
	 * The revocation value was embedded in the timestamp attribute (used in CAdES)
	 */
	TIMESTAMP_REVOCATION_VALUES(true),

	/**
	 * The revocation data was obtained from the ADBE attribute
	 */
	ADBE_REVOCATION_INFO_ARCHIVAL(true),
	
	/**
	 * The revocation data was embedded to Signature (all internal cases)
	 */
	SIGNATURE(true),

	/**
	 * The revocation data was provided by the user or online OCSP/CRL
	 */
	EXTERNAL(false),
	
	/**
	 * The revocation data was obtained from a local DB or cache
	 */
	CACHED(false);
	
	private final boolean internalOrigin;
	
	RevocationOrigin(final boolean internalOrigin) {
		this.internalOrigin = internalOrigin;
	}
	
	public boolean isInternalOrigin() {
		return internalOrigin;
	}

}
