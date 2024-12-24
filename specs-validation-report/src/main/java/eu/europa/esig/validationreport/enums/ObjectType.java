/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.validationreport.enums;

import eu.europa.esig.dss.enumerations.UriBasedEnum;

/**
 * Defines object types
 */
public enum ObjectType implements UriBasedEnum {

	/** Certificate */
	CERTIFICATE("urn:etsi:019102:validationObject:certificate"),

	/** CRL */
	CRL("urn:etsi:019102:validationObject:CRL"),

	/** OCSP response */
	OCSP_RESPONSE("urn:etsi:019102:validationObject:OCSPResponse"),

	/** TimeStamp */
	TIMESTAMP("urn:etsi:019102:validationObject:timestamp"),

	/** Evidence record */
	EVIDENCE_RECORD("urn:etsi:019102:validationObject:evidencerecord"),

	/** Public Key */
	PUBLIC_KEY("urn:etsi:019102:validationObject:publicKey"),

	/** Signed data */
	SIGNED_DATA("urn:etsi:019102:validationObject:signedData"),

	/** Other */
	OTHER("urn:etsi:019102:validationObject:other");

	/** VR URI of the object type */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
	ObjectType(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
