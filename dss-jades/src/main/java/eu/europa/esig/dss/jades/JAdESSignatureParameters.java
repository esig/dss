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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;

import java.util.Objects;

/**
 * The parameters to create/extend a JAdES signature
 */
public class JAdESSignatureParameters extends AbstractSignatureParameters<JAdESTimestampParameters> {
	
	private static final long serialVersionUID = -5937995983705731252L;

	/**
	 * Defines if certificate chain binaries must be included into the signed header ('x5c' attribute)
	 *
	 * DEFAULT: TRUE (the certificate chain header will be included into the signed header)
	 */
	private boolean includeCertificateChain = true;
	
	/**
	 * Defines if the signature must incorporate its MimeType definition in the signed header ('typ' attribute)
	 *
	 * DEFAULT: TRUE (the signature MimeType will be included into the signed header)
	 */
	private boolean includeSignatureType = true;

	/**
	 * This property defines whether a 'kid' (key identifier) header parameter should be added to a protected header.
	 *
	 * NOTE: a signing certificate shall be provided to embed the 'kid' header
	 *
	 * DEFAULT: TRUE ('kid' header parameter is included into the signed header, provided that
	 *           the signing-certificate is defined within the signature parameters).
	 */
	private boolean includeKeyIdentifier = true;

	/**
	 * This property defines a value for the 'x5u' signed header parameter. The value shall refer to a URI where
	 * the X.509 public key certificate or certificate chain corresponding to the key used to digitally sign the JWS
	 * can be retrieved from.
	 *
	 * NOTE: use methods {@code #setSigningCertificate} and {@code #includeCertificateChain}
	 *       to disable encapsulation of the signing certificate and certificate chain binaries
	 *
	 * DEFAULT: NULL (the 'x5u' header parameter is not included)
	 */
	private String x509Url;
	
	/**
	 * Defines if the payload has to be base64url encoded
	 * If false, original signed document binaries will be used according to RFC 7797
	 * 
	 * NOTE: the parameter is independent from {@code base64UrlEncodedEtsiUComponents}
	 * 
	 * Default : TRUE (base64url encoded payload)
	 */
	private boolean base64UrlEncodedPayload = true;
	
	/**
	 * Defines if the items of the 'etsiU' unprotected headers will be incorporated
	 * in their corresponding base64url encodings, if FALSE the components will
	 * appear as clear JSON instances.
	 * The parameter is used for Serialization (or Flattened) format only with an unprotected header.
	 * All the components of 'etsiU' header shall appear in the same representation
	 * 
	 * NOTE: the parameter is independent from {@code base64UrlEncodedPayload}
	 * 
	 * Default : TRUE (base64url encoded etsiU components)
	 * 
	 */
	private boolean base64UrlEncodedEtsiUComponents = true;

	/**
	 * The DigestAlgorithm used to create a reference to a signing certificate,
	 * namely 'x5t#256' for SHA256 or 'x5t#o' for other algorithms
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA512;
	
	/**
	 * Defines a JWS signature type according to RFC 7515, 3. JSON Web Signature (JWS) Overview
	 * 
	 * Default: JWSSerializationType.COMPACT_SERIALIZATION
	 */
	private JWSSerializationType jwsSerializationType = JWSSerializationType.COMPACT_SERIALIZATION;
	
	/**
	 * Defines a used 'sigD' mechanism for a detached signature
	 */
	private SigDMechanism sigDMechanism;

	/**
	 * Identifies a type of claimed signing time header to be used on JAdES signature creation
	 */
	private JAdESSigningTimeType jadesSigningTimeType = JAdESSigningTimeType.IAT;

	/**
	 * Default constructor instantiating object with default parameters
	 */
	public JAdESSignatureParameters() {
		// empty
	}

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.JAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only JAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

	@Override
	public JAdESTimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new JAdESTimestampParameters();
		}
		return contentTimestampParameters;
	}

	@Override
	public JAdESTimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new JAdESTimestampParameters();
		}
		return signatureTimestampParameters;
	}
	
	@Override
	public JAdESTimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new JAdESTimestampParameters();
		}
		return archiveTimestampParameters;
	}

	/**
	 * Defines if complete certificate chain binaries must be included into the signed header ('x5c' attribute)
	 * 
	 * @return TRUE if the certificate chain must be included, FALSE otherwise
	 */
	public boolean isIncludeCertificateChain() {
		return includeCertificateChain;
	}

	/**
	 * Sets if complete certificate chain binaries must be included into the signed header
	 * Default: TRUE (the complete binaries will be included into the signed header)
	 * 
	 * @param includeCertificateChain if the certificate chain binaries must be included into the signed header
	 */
	public void setIncludeCertificateChain(boolean includeCertificateChain) {
		this.includeCertificateChain = includeCertificateChain;
	}

	/**
	 * Defines if the signature MimeType string must be included into the signed header ('typ' attribute)
	 * 
	 * @return TRUE if the MimeType string of the produced signature must be included, FALSE otherwise
	 */
	public boolean isIncludeSignatureType() {
		return includeSignatureType;
	}

	/**
	 * Sets if the signature MimeType string must be included into the signed header ('typ' attribute)
	 *
	 * Default: TRUE (the signature MimeType will be included into the signed header)
	 *
	 * @param includeSignatureType if the signature MimeType be included into the signed header
	 */
	public void setIncludeSignatureType(boolean includeSignatureType) {
		this.includeSignatureType = includeSignatureType;
	}

	/**
	 * Returns whether a 'kid' (key identifier) header parameter should be created
	 *
	 * @return TRUE if the 'kid' should be created, FALSE otherwise
	 */
	public boolean isIncludeKeyIdentifier() {
		return includeKeyIdentifier;
	}

	/**
	 * Sets whether a 'kid' (key identifier) header parameter should be created within a protected header,
	 * provided that a signing-certificate is defined within the signature parameters.
	 *
	 * DEFAULT : TRUE (the 'kid' header parameter is created)
	 *
	 * @param includeKeyIdentifier identifies whether 'kid' should be created (when a signing-certificate is provided)
	 */
	public void setIncludeKeyIdentifier(boolean includeKeyIdentifier) {
		this.includeKeyIdentifier = includeKeyIdentifier;
	}

	/**
	 * Returns the value of the 'x5u' header parameter if present
	 *
	 * @return {@link String}
	 */
	public String getX509Url() {
		return x509Url;
	}

	/**
	 * Sets the value for the 'x5u' signed header parameter. The value shall refer to a URI where
	 * the X.509 public key certificate or certificate chain corresponding to the key used to digitally sign the JWS
	 * can be retrieved from.
	 * <p>
	 * NOTE: use methods {@code #setSigningCertificate} and {@code #includeCertificateChain}
	 *       to disable encapsulation of the signing certificate and certificate chain binaries (included by default).
	 * <p>
	 * DEFAULT: NULL (the 'x5u' header parameter is not included)
	 *
	 * @param x509Url {@link String} value of 'x5u' header parameter
	 */
	public void setX509Url(String x509Url) {
		this.x509Url = x509Url;
	}

	/**
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm)}.
	 *
	 * @return {@link DigestAlgorithm} to be used for signing certificate digest representation
	 */
	public DigestAlgorithm getSigningCertificateDigestMethod() {
		return signingCertificateDigestMethod;
	}

	/**
	 * The digest method indicates the digest algorithm to be used to calculate the certificate digest
	 * to define a signing certificate ('x5t#256' for SHA256 or 'x5t#o' for other algorithms)
	 * Default: DigestAlgorithm.SHA256 ('x5t#256' attribute will be created)
	 *
	 * @param signingCertificateDigestMethod {@link DigestAlgorithm} to be used
	 */
	public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
		Objects.requireNonNull(signingCertificateDigestMethod, "SigningCertificateDigestMethod cannot be null!");
		this.signingCertificateDigestMethod = signingCertificateDigestMethod;
	}

	/**
	 * Gets JWSSerializationType
	 * 
	 * @return {@link JWSSerializationType}
	 */
	public JWSSerializationType getJwsSerializationType() {
		return jwsSerializationType;
	}

	/**
	 * Sets the JWSSerializationType
	 * Default: JWSSerializationType.COMPACT_SERIALIZATION
	 * 
	 * @param jwsSerializationType {@link JWSSerializationType}
	 */
	public void setJwsSerializationType(JWSSerializationType jwsSerializationType) {
		Objects.requireNonNull(jwsSerializationType, "JWSSerializationType cannot be null!");
		this.jwsSerializationType = jwsSerializationType;
	}

	/**
	 * Returns a SigDMechanism to use
	 * 
	 * @return {@link SigDMechanism}
	 */
	public SigDMechanism getSigDMechanism() {
		return sigDMechanism;
	}

	/**
	 * Sets SigDMechanism to use for a Detached signature
	 * 
	 * @param sigDMechanism {@link SigDMechanism}
	 */
	public void setSigDMechanism(SigDMechanism sigDMechanism) {
		this.sigDMechanism = sigDMechanism;
	}

	/**
	 * Returns the JAdES claimed signing-time header parameters to be used
	 *
	 * @return {@link JAdESSigningTimeType}
	 */
	public JAdESSigningTimeType getJadesSigningTimeType() {
		return jadesSigningTimeType;
	}

	/**
	 * Sets the claimed signing-time header parameters to be used.
	 * <p>
	 * Requirements ETSI TS 119 182-1, clause 6.3, for iat and sigT:
	 * Before 2025-07-15T00:00:00Z the generator should include the iat header parameter
	 * for indicating the claimed signing time in new JAdES signatures and should not include
	 * the iat header parameter for indicating the claimed signing time in new JAdES signatures.
	 * Starting at 2025-07-15T00:00:00Z the generator shall include the iat header parameter
	 * for indicating the claimed signing time in new JAdES signatures.
	 * <p>
	 * Default : IAT ('iat' header parameter will be used)
	 *
	 * @param jadesSigningTimeType {@link JAdESSigningTimeType}
	 */
	public void setJadesSigningTimeType(JAdESSigningTimeType jadesSigningTimeType) {
		this.jadesSigningTimeType = jadesSigningTimeType;
	}

	/**
	 * Gets if base64Url encoded payload shall be used
	 * 
	 * @return TRUE if to use base64url encoded payload, FALSE otherwise
	 */
	public boolean isBase64UrlEncodedPayload() {
		return base64UrlEncodedPayload;
	}

	/**
	 * Sets if base64Url encoded payload shall be used If FALSE, the unencoded
	 * (original) payload will be used according to RFC 7797
	 * 
	 * NOTE: some restrictions for payload content can apply when dealing with
	 * unencoded payload. For more information please see RFC 7797. 
	 * The parameter is independent from {@code base64UrlEncodedEtsiUComponents}
	 * 
	 * Default : TRUE (base64Url encoded payload will be used)
	 * 
	 * @param base64EncodedPayload true if the payload shall be present in its corresponding base64url encoding,
	 *                                FALSE otherwise
	 */
	public void setBase64UrlEncodedPayload(boolean base64EncodedPayload) {
		this.base64UrlEncodedPayload = base64EncodedPayload;
	}

	/**
	 * Gets if the instances of the 'etsiU' unprotected header shall appear in their
	 * corresponding base64url encoding
	 * 
	 * Default : TRUE (base64Url encoded etsiU components will be used)
	 * 
	 * @return TRUE if the components of 'etsiU' header shall appear in their
	 *         corresponding base64url encoding, otherwise in their clear JSON
	 *         incorporation
	 */
	public boolean isBase64UrlEncodedEtsiUComponents() {
		return base64UrlEncodedEtsiUComponents;
	}

	/**
	 * Sets if the instances of the 'etsiU' header shall appear in their
	 * corresponding base64url encoding. If FALSE the components of 'etsiU' will
	 * appear in their clear JSON incorporation. The parameter is used for
	 * Serialization (or Flattened) format only with unsigned properties.
	 * 
	 * NOTE: the parameter is independent from {@code base64UrlEncodedPayload}
	 * 
	 * Default : TRUE (base64url encoded etsiU components)
	 * 
	 * @param base64UrlEncodedEtsiUComponents if the components of 'etsiU' unsigned
	 *                                        header shall appear in their
	 *                                        corresponding base64url encoding, if
	 *                                        FALSE the components will appear in
	 *                                        their clear JSON incorporation
	 */
	public void setBase64UrlEncodedEtsiUComponents(boolean base64UrlEncodedEtsiUComponents) {
		this.base64UrlEncodedEtsiUComponents = base64UrlEncodedEtsiUComponents;
	}

}
