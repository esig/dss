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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;

import java.util.Date;
import java.util.Objects;

/**
 * The parameters to create/extend a JAdES signature
 */
public class JAdESSignatureParameters extends AbstractSignatureParameters<JAdESTimestampParameters> {
	
	private static final long serialVersionUID = -5937995983705731252L;

	/**
	 * Enumeration defining ways to embed the 'x5c' header into a JWS
	 */
	public enum X5CHeaderPlacement {
		/**
		 * Insert the 'x5c' header within the protected headers map (signed)
		 */
		protectedHeader,
		/**
		 * Insert the 'x5c' header within the unprotected headers map (unsigned)
		 */
		unprotectedHeader,
		/**
		 * Insert the 'x5c' header as an item within the 'etsiU' unprotected header array (unsigned)
		 */
		etsiU,
	}

	/**
	 * Defines if certificate chain binaries must be included into the signed header ('x5c' attribute)
	 * <p>
	 * DEFAULT: TRUE (the certificate chain header will be included into the signed header)
	 */
	private boolean includeCertificateChain = true;

	/**
	 * Defines the element within JWS to embed the 'x5c' header parameter into.
	 * Applies when the {@code includeCertificateChain} parameter is enabled.
	 * DEFAULT: X5CHeaderPlacement.protectedHeader ('x5c' is to be included within the protected header)
	 */
	private X5CHeaderPlacement x5cHeaderPlacement;
	
	/**
	 * Defines if the signature must incorporate its MimeType definition in the signed header ('typ' attribute)
	 * <p>
	 * DEFAULT: TRUE (the signature MimeType will be included into the signed header)
	 */
	private boolean includeSignatureType = true;

	/**
	 * Defines a MimeType of the signature to be created, to be provided within a signed header ('typ' attribute)
	 * <p>
	 * DEFAULT: The type is determined based on the JWS serialization type
	 */
	private String signatureType;

	/**
	 * This property defines whether a 'kid' (key identifier) header parameter should be added to a protected header.
	 * <p>
	 * NOTE: a signing certificate shall be provided to embed the 'kid' header
	 * <p>
	 * DEFAULT: TRUE ('kid' header parameter is included into the signed header, provided that
	 *           the signing-certificate is defined within the signature parameters).
	 */
	private boolean includeKeyIdentifier = true;

	/**
	 * The value of the 'kid' (key identifier) parameter to be embedded within the protected header of the signature
	 * <p>
	 * DEFAULT: when not defined and {@code includeKeyIdentifier} is enabled, the value of the embedded 'kid'
	 *          protected header corresponds to the IssuerSerial of the signing-certificate.
	 */
	private String keyIdentifier;

	/**
	 * This property defines the value of the 'cty' (content type) header parameter.
	 * When set, the value of 'cty' header parameter will be defined with a given String.
	 * If not set, the value of 'cty' header parameter will be derived from a MimeType of the signer document
	 * (except for detached packaging).
	 */
	private String contentType;

	/**
	 * This property defines a value for the 'x5u' signed header parameter. The value shall refer to a URI where
	 * the X.509 public key certificate or certificate chain corresponding to the key used to digitally sign the JWS
	 * can be retrieved from.
	 * <p>
	 * NOTE: use methods {@code #setSigningCertificate} and {@code #includeCertificateChain}
	 *       to disable encapsulation of the signing certificate and certificate chain binaries
	 * <p>
	 * DEFAULT: NULL (the 'x5u' header parameter is not included)
	 */
	private String x509Url;
	
	/**
	 * Defines if the payload has to be base64url encoded
	 * If false, original signed document binaries will be used according to RFC 7797
	 * <p>
	 * NOTE: the parameter is independent from {@code base64UrlEncodedEtsiUComponents}
	 * <p>
	 * Default : TRUE (base64url encoded payload)
	 */
	private boolean base64UrlEncodedPayload = true;
	
	/**
	 * Defines if the items of the 'etsiU' unprotected headers will be incorporated
	 * in their corresponding base64url encodings, if FALSE the components will
	 * appear as clear JSON instances.
	 * The parameter is used for Serialization (or Flattened) format only with an unprotected header.
	 * All the components of 'etsiU' header shall appear in the same representation
	 * <p>
	 * NOTE: the parameter is independent from {@code base64UrlEncodedPayload}
	 * <p>
	 * Default : TRUE (base64url encoded etsiU components)
	 */
	private Boolean base64UrlEncodedEtsiUComponents;

	/**
	 * The DigestAlgorithm used to create a reference to a signing certificate,
	 * namely 'x5t#256' for SHA256 or 'x5t#o' for other algorithms
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA512;
	
	/**
	 * Defines a JWS signature type according to RFC 7515, 3. JSON Web Signature (JWS) Overview
	 * <p>
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
	 * The value of the 'exp' (expiration time) signed header parameter as per ETSI TS 119 411-5.
	 * The value is used for a TLS Certificate Binding signature and contains the expiry date of the binding.
	 */
	private Date expirationTime;

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
	 * Gets the placement of the 'x5c' header parameter
	 *
	 * @return {@link X5CHeaderPlacement}
	 */
	public X5CHeaderPlacement getX5CHeaderPlacement() {
		return x5cHeaderPlacement;
	}

	/**
	 * Sets the placement of the 'x5c' header parameter within the JWS structure.
	 * Applies when the {@code includeCertificateChain} parameter is enabled.
	 * DEFAULT: X5ChainHeaderPlacement.protectedHeader ('x5c' is to be included within the protected header)
	 *
	 * @param x5cHeaderPlacement {@link X5CHeaderPlacement}
	 */
	public void setX5CHeaderPlacement(X5CHeaderPlacement x5cHeaderPlacement) {
		this.x5cHeaderPlacement = x5cHeaderPlacement;
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
	 * <p>
	 * Default: TRUE (the signature MimeType will be included into the signed header)
	 *
	 * @param includeSignatureType if the signature MimeType be included into the signed header
	 */
	public void setIncludeSignatureType(boolean includeSignatureType) {
		this.includeSignatureType = includeSignatureType;
	}

	/**
	 * Gets the MimeType of the signature, to be incorporated in the signed header ('typ' attribute)
	 *
	 * @return {@link String}
	 */
	public String getSignatureType() {
		return signatureType;
	}

	/**
	 * Sets the MimeType of the signature to be incorporated within the signed header ('typ' attribute)
	 * <p>
	 * Default: The signature type is derived from the selected JWS serialization type
	 *
	 * @param signatureType {@link String}
	 */
	public void setSignatureType(String signatureType) {
		this.signatureType = signatureType;
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
	 * <p>
	 * DEFAULT : TRUE (the 'kid' header parameter is created)
	 *
	 * @param includeKeyIdentifier identifies whether 'kid' should be created (when a signing-certificate is provided)
	 */
	public void setIncludeKeyIdentifier(boolean includeKeyIdentifier) {
		this.includeKeyIdentifier = includeKeyIdentifier;
	}

	/**
	 * Gets the value of the 'kid' (key identifier) protected header parameter.
	 *
	 * @return {@link String}
	 */
	public String getKeyIdentifier() {
		return keyIdentifier;
	}

	/**
	 * Sets the 'kid' value to be incorporated within the signature's protected header.
	 * <p>
	 * DEFAULT: when not defined and {@code includeKeyIdentifier} is enabled, the value of the embedded 'kid'
	 *          protected header corresponds to the IssuerSerial of the signing-certificate.
	 *
	 * @param keyIdentifier {@link String}
	 */
	public void setKeyIdentifier(String keyIdentifier) {
		this.keyIdentifier = keyIdentifier;
	}

	/**
	 * Gets value of the 'cty' (content type) signed header parameter is to be included in
	 * a protected header of the signature.
	 *
	 * @return {@link String} value of the 'cty' (content type) signed header parameter
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Sets value of the 'cty' (content type) signed header parameter is to be included in
	 * a protected header of the signature.
	 * When set, the 'cty' (content type) protected header parameter will be created and use the given value
	 * (omitting "application/" prefix, if applicable).
	 * If not set, the value of the 'cty' (content type) protected header parameter will be derived from
	 * a MimeType of the signer document (except when a 'sigD' mechanism is used).
	 *
	 * @param contentType {@link String} value of the 'cty' (content type) signed header parameter
	 *                                   to be included in a protected header of the signature
	 */
	public void setContentType(String contentType) {
		this.contentType = contentType;
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
	 * Default: DigestAlgorithm.SHA512 ('x5t#o' attribute will be created)
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
	 * Gets the expiration time of the signature.
	 * NOTE: The signed header is used for an ETSI TS 119 411-5 TLS Certificate Binding signature and
	 * contains an expiry date of the binding.
	 *
	 * @return {@link Date}
	 */
	public Date getExpirationTime() {
		return expirationTime;
	}

	/**
	 * Sets the value for the 'exp' (expiration time) signed header of the signature.
	 * The claim identifies the expiration time on or after which the signature should not be accepted for processing.
	 * NOTE: The signed header is used for an ETSI TS 119 411-5 TLS Certificate Binding signature and
	 * contains an expiry date of the binding.
	 *
	 * @param expirationTime {@link Date}
	 */
	public void setExpirationTime(Date expirationTime) {
		this.expirationTime = expirationTime;
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
	 * <p>
	 * NOTE: some restrictions for payload content can apply when dealing with
	 * unencoded payload. For more information please see RFC 7797. 
	 * The parameter is independent from {@code base64UrlEncodedEtsiUComponents}
	 * <p>
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
	 * <p>
	 * Default : TRUE (base64Url encoded etsiU components will be used)
	 * 
	 * @return TRUE if the components of 'etsiU' header shall appear in their
	 *         corresponding base64url encoding, otherwise in their clear JSON
	 *         incorporation
	 */
	public Boolean isBase64UrlEncodedEtsiUComponents() {
		return base64UrlEncodedEtsiUComponents;
	}

	/**
	 * Sets if the instances of the 'etsiU' header shall appear in their
	 * corresponding base64url encoding. If FALSE the components of 'etsiU' will
	 * appear in their clear JSON incorporation. The parameter is used for
	 * Serialization (or Flattened) format only with unsigned properties.
	 * <p>
	 * NOTE: the parameter is independent from {@code base64UrlEncodedPayload}
	 * <p>
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

	@Override
	public String toString() {
		return "JAdESSignatureParameters [" +
				"includeCertificateChain=" + includeCertificateChain +
				", includeSignatureType=" + includeSignatureType +
				", includeKeyIdentifier=" + includeKeyIdentifier +
				", x509Url='" + x509Url + '\'' +
				", base64UrlEncodedPayload=" + base64UrlEncodedPayload +
				", base64UrlEncodedEtsiUComponents=" + base64UrlEncodedEtsiUComponents +
				", signingCertificateDigestMethod=" + signingCertificateDigestMethod +
				", jwsSerializationType=" + jwsSerializationType +
				", sigDMechanism=" + sigDMechanism +
				", jadesSigningTimeType=" + jadesSigningTimeType +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;

		JAdESSignatureParameters that = (JAdESSignatureParameters) o;
		return includeCertificateChain == that.includeCertificateChain
				&& includeSignatureType == that.includeSignatureType
				&& includeKeyIdentifier == that.includeKeyIdentifier
				&& base64UrlEncodedPayload == that.base64UrlEncodedPayload
				&& base64UrlEncodedEtsiUComponents == that.base64UrlEncodedEtsiUComponents
				&& Objects.equals(x509Url, that.x509Url)
				&& signingCertificateDigestMethod == that.signingCertificateDigestMethod
				&& jwsSerializationType == that.jwsSerializationType
				&& sigDMechanism == that.sigDMechanism
				&& jadesSigningTimeType == that.jadesSigningTimeType;
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Boolean.hashCode(includeCertificateChain);
		result = 31 * result + Boolean.hashCode(includeSignatureType);
		result = 31 * result + Boolean.hashCode(includeKeyIdentifier);
		result = 31 * result + Objects.hashCode(x509Url);
		result = 31 * result + Boolean.hashCode(base64UrlEncodedPayload);
		result = 31 * result + Boolean.hashCode(base64UrlEncodedEtsiUComponents);
		result = 31 * result + Objects.hashCode(signingCertificateDigestMethod);
		result = 31 * result + Objects.hashCode(jwsSerializationType);
		result = 31 * result + Objects.hashCode(sigDMechanism);
		result = 31 * result + Objects.hashCode(jadesSigningTimeType);
		return result;
	}

}
