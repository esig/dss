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

public interface SubIndication {

	String NONE = "";
	String NO_SIGNER_CERTIFICATE_FOUND = "NO_SIGNER_CERTIFICATE_FOUND";
	String FORMAT_FAILURE = "FORMAT_FAILURE";
	String NO_POLICY = "NO_POLICY";
	String POLICY_PROCESSING_ERROR = "POLICY_PROCESSING_ERROR";
	String OUT_OF_BOUNDS_NO_POE = "OUT_OF_BOUNDS_NO_POE";
	String NO_CERTIFICATE_CHAIN_FOUND = "NO_CERTIFICATE_CHAIN_FOUND";
	String TRY_LATER = "TRY_LATER";
	String REVOKED_NO_POE = "REVOKED_NO_POE";
	String REVOKED_CA_NO_POE = "REVOKED_CA_NO_POE";
	String CHAIN_CONSTRAINTS_FAILURE = "CHAIN_CONSTRAINTS_FAILURE";
	String CRYPTO_CONSTRAINTS_FAILURE = "CRYPTO_CONSTRAINTS_FAILURE";
	String CRYPTO_CONSTRAINTS_FAILURE_NO_POE = "CRYPTO_CONSTRAINTS_FAILURE_NO_POE";
	String SIGNED_DATA_NOT_FOUND = "SIGNED_DATA_NOT_FOUND";
	String HASH_FAILURE = "HASH_FAILURE";
	String SIG_CRYPTO_FAILURE = "SIG_CRYPTO_FAILURE";
	String SIG_CONSTRAINTS_FAILURE = "SIG_CONSTRAINTS_FAILURE";
	String NO_VALID_TIMESTAMP = "NO_VALID_TIMESTAMP";
	String NO_TIMESTAMP = "NO_TIMESTAMP";
	String NOT_YET_VALID = "NOT_YET_VALID";
	String TIMESTAMP_ORDER_FAILURE = "TIMESTAMP_ORDER_FAILURE";
	String REVOKED = "REVOKED";
	String EXPIRED = "EXPIRED";
	String NO_POE = "NO_POE";

	/**
	 * Added to handle the constraint on the timestamp delay in case where no signing-time property/attribute is present.
	 */
	String CLAIMED_SIGNING_TIME_ABSENT = "CLAIMED_SIGNING_TIME_ABSENT";
	/**
	 * Added to handle any unexpected error encountered during the validation process.
	 */
	String UNEXPECTED_ERROR = "UNEXPECTED_ERROR";

}
