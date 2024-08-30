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

	/**
	 * The signature is not conformant to one of the base standards to the extent that the cryptographic
	 * verification building block is unable to process it.
	 */
	FORMAT_FAILURE("urn:etsi:019102:subindication:FORMAT_FAILURE"),

	/**
	 * The signature validation process results into TOTAL-FAILED because at least one hash of a
	 * signed data object(s) that has been included in the signing process does not match the
	 * corresponding hash value in the signature.
	 */
	HASH_FAILURE("urn:etsi:019102:subindication:HASH_FAILURE"),

	/**
	 * The signature validation process results into TOTAL-FAILED because the signature value in the
	 * signature could not be verified using the signer's public key in the signing certificate.
	 */
	SIG_CRYPTO_FAILURE("urn:etsi:019102:subindication:SIG_CRYPTO_FAILURE"),

	/**
	 * The signature validation process results into TOTAL-FAILED because:
	 * • the signing certificate has been revoked; and
	 * • there is proof that the signature has been created after the revocation time.
	 */
	REVOKED("urn:etsi:019102:subindication:REVOKED"),

	/**
	 * The signature validation process results into TOTAL-FAILED because there is proof that the
	 * signature has been created after the expiration date (notAfter) of the signing certificate.
	 */
	EXPIRED("urn:etsi:019102:subindication:EXPIRED"),

	/**
	 * The signature validation process results into TOTAL-FAILED because there is proof that the
	 * signature was created before the issuance date (notBefore) of the signing certificate.
	 */
	NOT_YET_VALID("urn:etsi:019102:subindication:NOT_YET_VALID"),

	/**
	 * The signature validation process results into INDETERMINATE because one or more attributes of
	 * the signature do not match the validation constraints.
	 */
	SIG_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:SIG_CONSTRAINTS_FAILURE"),

	/**
	 * The signature validation process results into INDETERMINATE because the certificate chain used
	 * in the validation process does not match the validation constraints related to the certificate.
	 */
	CHAIN_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CHAIN_CONSTRAINTS_FAILURE"),

	/**
	 * The signature validation process results into INDETERMINATE because the set of certificates
	 * available for chain validation produced an error for an unspecified reason.
	 */
	CERTIFICATE_CHAIN_GENERAL_FAILURE("urn:etsi:019102:subindication:CERTIFICATE_CHAIN_GENERAL_FAILURE"),

	/**
	 * The signature validation process results into INDETERMINATE because at least one of the
	 * algorithms that have been used in material (e.g. the signature value, a certificate...) involved in
	 * validating the signature, or the size of a key used with such an algorithm, is below the required
	 * cryptographic security level, and:
	 * • this material was produced after the time up to which this algorithm/key was
	 * considered secure (if such a time is known); and
	 * • the material is not protected by a sufficiently strong time-stamp applied before
	 * the time up to which the algorithm/key was considered secure (if such a time is known).
	 */
	CRYPTO_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE"),

	/**
	 * The signature validation process results into INDETERMINATE because a given formal policy file
	 * could not be processed for any reason (e.g. not accessible, not parseable, digest mismatch, etc.).
	 */
	POLICY_PROCESSING_ERROR("urn:etsi:019102:subindication:POLICY_PROCESSING_ERROR"),

	/**
	 * The signature validation process results into INDETERMINATE because the electronic document
	 * containing the details of the policy is not available.
	 */
	SIGNATURE_POLICY_NOT_AVAILABLE("urn:etsi:019102:subindication:SIGNATURE_POLICY_NOT_AVAILABLE"),

	/**
	 * The signature validation process results into INDETERMINATE because some constraints on the
	 * order of signature time-stamps and/or signed data object(s) time-stamps are not respected.
	 */
	TIMESTAMP_ORDER_FAILURE("urn:etsi:019102:subindication:TIMESTAMP_ORDER_FAILURE"),

	/**
	 * The signature validation process results into INDETERMINATE because the signing certificate
	 * cannot be identified.
	 */
	NO_SIGNING_CERTIFICATE_FOUND("urn:etsi:019102:subindication:NO_SIGNING_CERTIFICATE_FOUND"),

	/**
	 * The signature validation process results into INDETERMINATE because no certificate chain has
	 * been found for the identified signing certificate.
	 */
	NO_CERTIFICATE_CHAIN_FOUND("urn:etsi:019102:subindication:NO_CERTIFICATE_CHAIN_FOUND"),

	/**
	 * The signature validation process results into INDETERMINATE because no certificate chain has been found
	 * for the identified signing certificate due to the trust anchor not being trusted at the validation
	 * date/time by the validation policy in use. However the Signature Validation Algorithm
	 * cannot ascertain that the signing time lies before or after a time when the trust anchor
	 * was trusted by the validation policy in use.
	 */
	NO_CERTIFICATE_CHAIN_FOUND_NO_POE("urn:etsi:019102:subindication:NO_CERTIFICATE_CHAIN_FOUND_NO_POE"),

	/**
	 * The signature validation process results into INDETERMINATE because the signing certificate was
	 * revoked at the validation date/time. However, the Signature Validation Algorithm cannot ascertain that the
	 * signing time lies before or after the revocation time.
	 */
	REVOKED_NO_POE("urn:etsi:019102:subindication:REVOKED_NO_POE"),

	/**
	 * The signature validation process results into INDETERMINATE because at least one certificate
	 * chain was found but an intermediate CA certificate is revoked.
	 */
	REVOKED_CA_NO_POE("urn:etsi:019102:subindication:REVOKED_CA_NO_POE"),

	/**
	 * The signature validation process results into INDETERMINATE because the signing certificate is
	 * expired or not yet valid at the validation date/time and the Signature Validation Algorithm
	 * cannot ascertain that the signing time lies within the validity interval of the signing certificate. The
	 * certificate is known not to be revoked.
	 */
	OUT_OF_BOUNDS_NOT_REVOKED("urn:etsi:019102:subindication:OUT_OF_BOUNDS_NOT_REVOKED"),

	/**
	 * The signature validation process results into INDETERMINATE because the signing certificate is
	 * expired or not yet valid at the validation date/time and the Signature Validation Algorithm
	 * cannot ascertain that the signing time lies within the validity interval of the signing certificate.
	 */
	OUT_OF_BOUNDS_NO_POE("urn:etsi:019102:subindication:OUT_OF_BOUNDS_NO_POE"),

	/**
	 * The signature validation process results into INDETERMINATE because the signing certificate
	 * of the revocation information of the signature signing certificate is expired or not yet valid
	 * at the validation date/time and the Signature Validation Algorithm cannot ascertain that
	 * the revocation information issuance time lies within the validity interval of the signing certificate
	 * of that revocation information.
	 */
	REVOCATION_OUT_OF_BOUNDS_NO_POE("urn:etsi:019102:subindication:REVOCATION_OUT_OF_BOUNDS_NO_POE"),

	/**
	 * The signature validation process results into INDETERMINATE because at least one of the
	 * algorithms that have been used in objects (e.g. the signature value, a certificate, etc.) involved in
	 * validating the signature, or the size of a key used with such an algorithm, is below the required
	 * cryptographic security level, and there is no proof that this material was produced before the time up
	 * to which this algorithm/key was considered secure
	 */
	CRYPTO_CONSTRAINTS_FAILURE_NO_POE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),

	/**
	 * The signature validation process results into INDETERMINATE because a proof of existence is
	 * missing to ascertain that a signed object has been produced before some compromising event
	 * (e.g. broken algorithm).
	 */
	NO_POE("urn:etsi:019102:subindication:NO_POE"),

	/**
	 * The signature validation process results into INDETERMINATE because not all constraints can be
	 * fulfilled using available information. However, it may be possible to do so using additional revocation
	 * information that will be available at a later point of time.
	 */
	TRY_LATER("urn:etsi:019102:subindication:TRY_LATER"),

	/**
	 * The signature validation process results into INDETERMINATE because signed data cannot be
	 * obtained.
	 */
	SIGNED_DATA_NOT_FOUND("urn:etsi:019102:subindication:SIGNED_DATA_NOT_FOUND");

	/** VR URI of the SubIndication */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
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
