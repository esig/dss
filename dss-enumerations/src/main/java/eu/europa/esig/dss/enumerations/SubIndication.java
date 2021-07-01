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
 * Sub indication values
 * 
 * Source ETSI EN 319 102-1
 */
public enum SubIndication implements UriBasedEnum {

	FORMAT_FAILURE("urn:etsi:019102:subindication:FORMAT_FAILURE"),

	HASH_FAILURE("urn:etsi:019102:subindication:HASH_FAILURE"),

	SIG_CRYPTO_FAILURE("urn:etsi:019102:subindication:SIG_CRYPTO_FAILURE"),

	REVOKED("urn:etsi:019102:subindication:REVOKED"),

	SIG_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:SIG_CONSTRAINTS_FAILURE"),

	CHAIN_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CHAIN_CONSTRAINTS_FAILURE"),

	CERTIFICATE_CHAIN_GENERAL_FAILURE("urn:etsi:019102:subindication:CERTIFICATE_CHAIN_GENERAL_FAILURE"),

	CRYPTO_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE"),

	EXPIRED("urn:etsi:019102:subindication:EXPIRED"),

	NOT_YET_VALID("urn:etsi:019102:subindication:NOT_YET_VALID"),

	POLICY_PROCESSING_ERROR("urn:etsi:019102:subindication:POLICY_PROCESSING_ERROR"),

	SIGNATURE_POLICY_NOT_AVAILABLE("urn:etsi:019102:subindication:SIGNATURE_POLICY_NOT_AVAILABLE"),

	TIMESTAMP_ORDER_FAILURE("urn:etsi:019102:subindication:TIMESTAMP_ORDER_FAILURE"),

	NO_SIGNING_CERTIFICATE_FOUND("urn:etsi:019102:subindication:NO_SIGNING_CERTIFICATE_FOUND"),

	NO_CERTIFICATE_CHAIN_FOUND("urn:etsi:019102:subindication:NO_CERTIFICATE_CHAIN_FOUND"),

	REVOKED_NO_POE("urn:etsi:019102:subindication:REVOKED_NO_POE"),

	REVOKED_CA_NO_POE("urn:etsi:019102:subindication:REVOKED_CA_NO_POE"),

	OUT_OF_BOUNDS_NO_POE("urn:etsi:019102:subindication:OUT_OF_BOUNDS_NO_POE"),

	REVOCATION_OUT_OF_BOUNDS_NO_POE("urn:etsi:019102:subindication:REVOCATION_OUT_OF_BOUNDS_NO_POE"),

	OUT_OF_BOUNDS_NOT_REVOKED("urn:etsi:019102:subindication:OUT_OF_BOUNDS_NOT_REVOKED"),

	CRYPTO_CONSTRAINTS_FAILURE_NO_POE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),

	NO_POE("urn:etsi:019102:subindication:NO_POE"),

	TRY_LATER("urn:etsi:019102:subindication:TRY_LATER"),

	SIGNED_DATA_NOT_FOUND("urn:etsi:019102:subindication:SIGNED_DATA_NOT_FOUND");

	private final String uri;

	SubIndication(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

	/**
	 * SubIndication can be null
	 * 
	 * @param value
	 *            the string value to be converted
	 * @return the related SubIndication
	 */
	public static SubIndication forName(String value) {
		if ((value != null) && !value.isEmpty()) {
			return SubIndication.valueOf(value);
		}
		return null;
	}

}
