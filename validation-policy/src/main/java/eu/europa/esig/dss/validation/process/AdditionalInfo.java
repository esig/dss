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
package eu.europa.esig.dss.validation.process;

public final class AdditionalInfo {

	private AdditionalInfo() {
	}

	public static final String BEST_SIGNATURE_TIME = "Best signature time : {0}";

	public static final String CERTIFICATE_VALIDITY = "Certificate validity : {0} to {1}";

	public static final String CONTROL_TIME = "Control time : {0}";
	
	public static final String CRYPTOGRAPHIC_CHECK_FAILURE = "Algorithm [{0}] is not reliable at the validation time : {1}";
	
	public static final String CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID = "Algorithm [{0}] is not reliable at the validation time : {1} for token with ID [{2}]";
	
	public static final String REVOCATION_CRYPTOGRAPHIC_CHECK_FAILURE = "Revocation data for certificate with id [{0}] is not reliable";
	
	public static final String REVOCATON_ACCEPTANCE_CHECK = "Id = {0}, production date = {1}";

	public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm";

	public static final String KEY_USAGE = "Key usage : {0}";

	public static final String EXTENDED_KEY_USAGE = "Extended key usage : {0}";
	
	public static final String REVOCATION_CHECK = "Validation time : {0}; Production time : {1}; NextUpdate time : {2}";
	
	public static final String REVOCATION_NO_THIS_UPDATE = "The revocation data {0} does not have thisUpdate date";
	
	public static final String REVOCATION_THIS_UPDATE_BEFORE = "Revocation {0} thisUpdate date {1} is before the certificate validity range : {2} - {3}";
	
	public static final String REVOCATION_NOT_AFTER_AFTER = "Revocation {0} notAfterDate {1} is beyond the certificate validity range : {2} - {3}";
	
	public static final String REVOCATION_CERT_HASH_OK = "CertHash value of Revocation {0} matches with the certificate digest";
	
	public static final String REVOCATION_CONSISTENT = "Revocation {0} thisUpdate {1} is in the certificate validity range : {2} - {3}";

	public static final String PSEUDO = "Pseudo : {0}";

	public static final String REVOCATION = "Revocation reason : {0} (date : {1})";

	public static final String VALIDATION_TIME = "Validation time : {0}";

	public static final String VALIDATION_TIME_WITH_ID = "Validation time : {0} for token with ID : [{1}]";

	public static final String TRUST_SERVICE_NAME = "Trust service name : {0}";

	public static final String TRUSTED_SERVICE_STATUS = "Status : {0}";

	public static final String TRUSTED_SERVICE_TYPE = "Type : {0}";

	public static final String TRUSTED_LIST = "Trusted List : {0}";

}
