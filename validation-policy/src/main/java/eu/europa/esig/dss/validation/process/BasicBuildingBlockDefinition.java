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

import eu.europa.esig.dss.enumerations.UriBasedEnum;

/**
 * Definition of signature Basic Building Blocks
 */
public enum BasicBuildingBlockDefinition implements UriBasedEnum {

	FORMAT_CHECKING("urn:cef:dss:bbb:formatChecking"),

	IDENTIFICATION_OF_THE_SIGNING_CERTIFICATE("urn:cef:dss:bbb:identificationOfTheSigningCertificate"),

	VALIDATION_CONTEXT_INITIALIZATION("urn:cef:dss:bbb:validationContextInitialization"),

	CRYPTOGRAPHIC_VERIFICATION("urn:cef:dss:bbb:cryptographicVerification"),

	SIGNATURE_ACCEPTANCE_VALIDATION("urn:cef:dss:bbb:signatureAcceptanceValidation"),

	X509_CERTIFICATE_VALIDATION("urn:cef:dss:bbb:x509CertificateValidation"),

	REVOCATION_FRESHNESS_CHECKER("urn:cef:dss:bbb:revocationFreshnessChecker"),

	PAST_SIGNATURE_VALIDATION("urn:cef:dss:bbb:pastSignatureValidation"),

	PAST_CERTIFICATE_VALIDATION("urn:cef:dss:bbb:pastCertificateValidation"),

	VALIDATION_TIME_SLIDING("urn:cef:dss:bbb:validationTimeSliding");

	private final String uri;

	BasicBuildingBlockDefinition(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
