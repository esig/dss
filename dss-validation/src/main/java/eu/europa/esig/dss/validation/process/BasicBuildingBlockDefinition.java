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
package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.enumerations.UriBasedEnum;

/**
 * Definition of signature Basic Building Blocks as per EN 319 102-1
 *
 */
public enum BasicBuildingBlockDefinition implements UriBasedEnum {

	/** 5.2.2 Format Checking */
	FORMAT_CHECKING("urn:cef:dss:bbb:formatChecking"),

	/** 5.2.3 Identification of the signing certificate */
	IDENTIFICATION_OF_THE_SIGNING_CERTIFICATE("urn:cef:dss:bbb:identificationOfTheSigningCertificate"),

	/** 5.2.4 Validation context initialization */
	VALIDATION_CONTEXT_INITIALIZATION("urn:cef:dss:bbb:validationContextInitialization"),

	/** 5.2.5 Revocation freshness checker  */
	REVOCATION_FRESHNESS_CHECKER("urn:cef:dss:bbb:revocationFreshnessChecker"),

	/** 5.2.6 X.509 certificate validation */
	X509_CERTIFICATE_VALIDATION("urn:cef:dss:bbb:x509CertificateValidation"),

	/** 5.2.7 Cryptographic verification */
	CRYPTOGRAPHIC_VERIFICATION("urn:cef:dss:bbb:cryptographicVerification"),

	/** 5.2.8 Signature Acceptance Validation (SAV) */
	SIGNATURE_ACCEPTANCE_VALIDATION("urn:cef:dss:bbb:signatureAcceptanceValidation"),

	/** 5.6.2.1 Past certificate validation */
	PAST_CERTIFICATE_VALIDATION("urn:cef:dss:bbb:pastCertificateValidation"),

	/** 5.6.2.2 Validation time sliding process */
	VALIDATION_TIME_SLIDING("urn:cef:dss:bbb:validationTimeSliding"),

	/** 5.6.2.4 Past signature validation building block */
	PAST_SIGNATURE_VALIDATION("urn:cef:dss:bbb:pastSignatureValidation");

	/** URI identifying the BasicBuildingBlock */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
	BasicBuildingBlockDefinition(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
