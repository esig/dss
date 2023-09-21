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
 * The list of possible values for indications.
 * 
 * Source ETSI EN 319 102-1
 */
public enum Indication implements UriBasedEnum {

	/*
	 * When present in the validation report of a signature, the following URIs
	 * shall be used to represent the main status indication:
	 */

	/**
	 * When the cryptographic checks of the signature (including checks of hashes of individual data
	 * objects that have been signed indirectly) succeeded as well as all checks prescribed by the
	 * signature validation policy have been passed.
	 */
	TOTAL_PASSED("urn:etsi:019102:mainindication:total-passed"),

	/**
	 * The cryptographic checks of the signature failed (including checks of hashes of individual data
	 * objects that have been signed indirectly), or it is proven that the signing certificate was invalid
	 * at the time of generation of the signature, or because the signature is not conformant to one of
	 * the base standards to the extent that the cryptographic verification building block is unable to
	 * process it.
	 */
	TOTAL_FAILED("urn:etsi:019102:mainindication:total-failed"),

	/**
	 * The results of the performed checks do not allow to ascertain the signature to be
	 * TOTAL-PASSED or TOTAL-FAILED.
	 */
	INDETERMINATE("urn:etsi:019102:mainindication:indeterminate"),

	/*
	 * When present in an individual validation constraint report element (see
	 * clause 4.3.5.4) or a validation report of a signature validation object (see
	 * clause 4.4.8), the following URIs shall be used to represent the main status
	 * indication:
	 */

	/** When an individual constrain validation succeeds */
	PASSED("urn:etsi:019102:mainindication:passed"),

	/** When an individual constrain validation fails */
	FAILED("urn:etsi:019102:mainindication:failed"),

	/** When no signature is found within the document (empty report is not permitted) */
	NO_SIGNATURE_FOUND("urn:cef:dss:mainindication:noSignatureFound");

	/** The indication VR URI */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
	Indication(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
