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
package eu.europa.esig.dss.validation.policy.rules;

/**
 * Sub indication values
 * 
 * Source ETSI EN 319 102-1
 */
public enum SubIndication {

	NO_SIGNING_CERTIFICATE_FOUND,

	FORMAT_FAILURE,

	POLICY_PROCESSING_ERROR,

	SIGNATURE_POLICY_NOT_AVAILABLE,

	OUT_OF_BOUNDS_NO_POE,

	NO_CERTIFICATE_CHAIN_FOUND,

	TRY_LATER,

	REVOKED_NO_POE,

	REVOKED_CA_NO_POE,

	CHAIN_CONSTRAINTS_FAILURE,

	CRYPTO_CONSTRAINTS_FAILURE,

	CRYPTO_CONSTRAINTS_FAILURE_NO_POE,

	SIGNED_DATA_NOT_FOUND,

	HASH_FAILURE,

	SIG_CRYPTO_FAILURE,

	SIG_CONSTRAINTS_FAILURE,

	NOT_YET_VALID,

	TIMESTAMP_ORDER_FAILURE,

	REVOKED,

	EXPIRED,

	NO_POE,

	CERTIFICATE_CHAIN_GENERAL_FAILURE,

	/**
	 * Added to handle any unexpected error encountered during the validation process.
	 */
	UNEXPECTED_ERROR;

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
