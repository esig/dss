/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.rules;

public interface SubIndication {

	public static final String NONE = "";
	public static final String NO_SIGNER_CERTIFICATE_FOUND = "NO_SIGNER_CERTIFICATE_FOUND";
	public static final String FORMAT_FAILURE = "FORMAT_FAILURE";
	public static final String NO_POLICY = "NO_POLICY";
	public static final String POLICY_PROCESSING_ERROR = "POLICY_PROCESSING_ERROR";
	public static final String OUT_OF_BOUNDS_NO_POE = "OUT_OF_BOUNDS_NO_POE";
	public static final String NO_CERTIFICATE_CHAIN_FOUND = "NO_CERTIFICATE_CHAIN_FOUND";
	public static final String TRY_LATER = "TRY_LATER";
	public static final String REVOKED_NO_POE = "REVOKED_NO_POE";
	public static final String REVOKED_CA_NO_POE = "REVOKED_CA_NO_POE";
	public static final String CHAIN_CONSTRAINTS_FAILURE = "CHAIN_CONSTRAINTS_FAILURE";
	public static final String CRYPTO_CONSTRAINTS_FAILURE = "CRYPTO_CONSTRAINTS_FAILURE";
	public static final String CRYPTO_CONSTRAINTS_FAILURE_NO_POE = "CRYPTO_CONSTRAINTS_FAILURE_NO_POE";
	public static final String SIGNED_DATA_NOT_FOUND = "SIGNED_DATA_NOT_FOUND";
	public static final String HASH_FAILURE = "HASH_FAILURE";
	public static final String SIG_CRYPTO_FAILURE = "SIG_CRYPTO_FAILURE";
	public static final String SIG_CONSTRAINTS_FAILURE = "SIG_CONSTRAINTS_FAILURE";
	public static final String NO_VALID_TIMESTAMP = "NO_VALID_TIMESTAMP";
	public static final String NO_TIMESTAMP = "NO_TIMESTAMP";
	public static final String NOT_YET_VALID = "NOT_YET_VALID";
	public static final String TIMESTAMP_ORDER_FAILURE = "TIMESTAMP_ORDER_FAILURE";
	public static final String REVOKED = "REVOKED";
	public static final String EXPIRED = "EXPIRED";
	public static final String NO_POE = "NO_POE";

	/**
	 * Added to handle the constraint on the timestamp delay in case where no signing-time property/attribute is present.
	 */
	public static final String CLAIMED_SIGNING_TIME_ABSENT = "CLAIMED_SIGNING_TIME_ABSENT";
	/**
	 * Added to handle any unexpected error encountered during the validation process.
	 */
	public static final String UNEXPECTED_ERROR = "UNEXPECTED_ERROR";
	// public static final String = "";
	// public static final String = "";

}
