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
package eu.europa.esig.dss.model.x509;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.CertificateTokenIdentifier;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Whenever the signature validation process encounters an {@link java.security.cert.X509Certificate} a certificateToken
 * is created.<br>
 * This class encapsulates some frequently used information: a certificate comes from a certain context (Trusted List,
 * CertStore, Signature), has revocation data... To expedite the processing of such information, they are kept in cache.
 */
@SuppressWarnings("serial")
public class CertificateToken extends Token {

	/**
	 * Encapsulated X509 certificate.
	 */
	private final X509Certificate x509Certificate;
	
	/**
	 * Digest of the public key (cross certificates have same public key)
	 */
	private final EntityIdentifier entityKey;

	/**
	 * Indicates if the certificate is self-signed. This attribute stays null till the first call to
	 * {@link #isSelfSigned()} function.
	 */
	private Boolean selfSigned;
	
	/**
	 * Cached list of KeyUsageBit
	 */
	private List<KeyUsageBit> keyUsageBits;

	/**
	 * Creates a CertificateToken wrapping the provided X509Certificate.
	 *
	 * @param x509Certificate
	 *            the X509Certificate object
	 */
	public CertificateToken(X509Certificate x509Certificate) {
		Objects.requireNonNull(x509Certificate, "X509 certificate is missing");

		this.x509Certificate = x509Certificate;
		this.entityKey = new EntityIdentifier(x509Certificate.getPublicKey());

		// The Algorithm OID is used and not the name {@code x509Certificate.getSigAlgName()}
		this.signatureAlgorithm = SignatureAlgorithm.forOidAndParams(x509Certificate.getSigAlgOID(), x509Certificate.getSigAlgParams());
	}

	@Override
	public String getAbbreviation() {
		return getDSSIdAsString();
	}

	/**
	 * Returns the identifier of the current public key. Several certificate can have
	 * the same public key (cross-certificates)
	 * 
	 * @return {@link EntityIdentifier}
	 */
	public EntityIdentifier getEntityKey() {
		return entityKey;
	}

	/**
	 * Returns the public key associated with the certificate.<br>
	 * To get the encryption algorithm used with this public key call getAlgorithm() method.<br>
	 * RFC 2459:<br>
	 * 4.1.2.7 Subject Public Key Info
	 * This field is used to carry the public key and identify the algorithm with which the key is used. The algorithm
	 * is
	 * identified using the AlgorithmIdentifier structure specified in section 4.1.1.2. The object identifiers for the
	 * supported algorithms and the methods for encoding the public key materials (public key and parameters) are
	 * specified in section 7.3.
	 *
	 * @return the public key of the certificate
	 */
	public PublicKey getPublicKey() {
		return x509Certificate.getPublicKey();
	}
	
	/**
	 * Returns the expiration date of the certificate.
	 *
	 * @return the expiration date (notAfter)
	 */
	public Date getNotAfter() {
		return x509Certificate.getNotAfter();
	}

	/**
	 * Returns the issuance date of the certificate.
	 *
	 * @return the issuance date (notBefore)
	 */
	public Date getNotBefore() {
		return x509Certificate.getNotBefore();
	}

	@Override
	public Date getCreationDate() {
		return getNotBefore();
	}

	/**
	 * Checks if the given date is in the validity period of the certificate.
	 *
	 * @param date
	 *            the date to be tested
	 * @return true if the given date is in the certificate period validity
	 */
	public boolean isValidOn(final Date date) {
		if ((x509Certificate == null) || (date == null)) {
			return false;
		}
		try {
			x509Certificate.checkValidity(date);
			return true;
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			return false;
		}
	}

	/**
	 * Checks if the certificate is self-signed.
	 * 
	 * "Self-signed certificates are self-issued certificates where the digital signature may be verified by the public
	 * key bound into the certificate. Self-signed certificates are used to convey a public key for use to begin
	 * certification paths." [RFC5280]
	 *
	 * @return true if the certificate is a self-sign
	 */
	@Override
	public boolean isSelfSigned() {
		if (selfSigned == null) {
			selfSigned = isSelfIssued();
			if (selfSigned) {
				try {
					x509Certificate.verify(x509Certificate.getPublicKey());
					selfSigned = true;
					signatureValidity = SignatureValidity.VALID;
				} catch (Exception e) {
					selfSigned = false;
				}
			}
		} else if (selfSigned) {
			signatureValidity = SignatureValidity.VALID;
		}
		return selfSigned;
	}

	/**
	 * This method returns true if the certificate is self-issued.
	 * 
	 * "Self-issued certificates are CA certificates in which the issuer and subject are the same entity.
	 * Self-issued certificates are generated to support changes in policy or operations." [RFC5280]
	 * 
	 * @return true if the certificate is self-issued
	 */
	public boolean isSelfIssued() {
		final String n1 = x509Certificate.getSubjectX500Principal().getName(X500Principal.CANONICAL);
		final String n2 = x509Certificate.getIssuerX500Principal().getName(X500Principal.CANONICAL);
		return n1.equals(n2);
	}

	/**
	 * This method returns true if the given token is equivalent.
	 * 
	 * @param token
	 *              the token to be compared
	 * @return true if the given certificate has the same public key
	 */
	public boolean isEquivalent(CertificateToken token) {
		PublicKey currentPublicKey = getPublicKey();
		PublicKey tokenPublicKey = token.getPublicKey();
		return Arrays.equals(currentPublicKey.getEncoded(), tokenPublicKey.getEncoded());
	}

	/**
	 * Gets the enclosed X509 Certificate.
	 *
	 * @return the X509Certificate object
	 */
	public X509Certificate getCertificate() {
		return x509Certificate;
	}

	/**
	 * Returns the encoded form of this certificate. X.509 certificates would be encoded as ASN.1 DER.
	 *
	 * @return the encoded form of this certificate
	 */
	@Override
	public byte[] getEncoded() {
		try {
			return x509Certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new DSSException("Unable to encode the certificate", e);
		}
	}

	/**
	 * Gets the serialNumber value from the encapsulated certificate. The serial number is an integer assigned by the
	 * certification authority to each certificate. It must be unique for each certificate issued by a given CA.
	 *
	 * @return the certificate serial number
	 */
	public BigInteger getSerialNumber() {
		return x509Certificate.getSerialNumber();
	}

	/**
	 * Returns the subject as wrapped X500Principal with helpful methods
	 * @return an instance of X500PrincipalHelper with the SubjectX500Principal
	 */
	public X500PrincipalHelper getSubject() {
		return new X500PrincipalHelper(x509Certificate.getSubjectX500Principal());
	}

	/**
	 * Returns the issuer as wrapped X500Principal with helpful methods
	 * @return an instance of X500PrincipalHelper with the IssuerX500Principal
	 */
	public X500PrincipalHelper getIssuer() {
		return new X500PrincipalHelper(x509Certificate.getIssuerX500Principal());
	}
	
	/**
	 * Returns the {@code X500Principal} of the certificate which was used to sign
	 * this token.
	 *
	 * @return the issuer's {@code X500Principal}
	 */
	@Override
	public X500Principal getIssuerX500Principal() {
		return x509Certificate.getIssuerX500Principal();
	}

	@Override
	protected SignatureValidity checkIsSignedBy(final PublicKey publicKey) {
		signatureValidity = SignatureValidity.INVALID;
		signatureInvalidityReason = "";
		try {
			x509Certificate.verify(publicKey);
			signatureValidity = SignatureValidity.VALID;
		} catch (NoSuchProviderException e) { // if there's no default provider.
			throw new DSSException(String.format("No provider has been found for signature validation : %s", e.getMessage()), e);
		} catch (Exception e) {
			signatureInvalidityReason = e.getClass().getSimpleName() + " : " + e.getMessage();
		}
		return signatureValidity;
	}

	/**
	 * This method checks if the certificate contains the given key usage bit.
	 *
	 * @param keyUsageBit
	 *            the keyUsageBit to be checked.
	 * @return true if contains
	 */
	public boolean checkKeyUsage(final KeyUsageBit keyUsageBit) {
		return getKeyUsageBits().contains(keyUsageBit);
	}

	/**
	 * This method returns a list {@code KeyUsageBit} representing the key usages of the certificate.
	 *
	 * @return {@code List} of {@code KeyUsageBit}s of different certificate's key usages
	 */
	public List<KeyUsageBit> getKeyUsageBits() {
		if (keyUsageBits == null) {
			keyUsageBits = new ArrayList<>();
			final boolean[] keyUsageArray = x509Certificate.getKeyUsage();
			if (keyUsageArray != null) {
				for (KeyUsageBit keyUsageBit : KeyUsageBit.values()) {
					if (keyUsageArray[keyUsageBit.getIndex()]) {
						keyUsageBits.add(keyUsageBit);
					}
				}
			}
		}
		return keyUsageBits;
	}

	/**
	 * This method checks if the BasicConstraint is present
	 * 
	 * @return true if the certificate is defined as a CA
	 */
	public boolean isCA() {
		return x509Certificate.getBasicConstraints() != -1;
	}

	/**
	 * This method returns a PathLenConstraint value when BasicConstraint and the attribute itself are present,
	 * and cA parameters is set to true.
	 *
	 * @return PathLenConstraint integer value, when present. -1 otherwise
	 */
	public int getPathLenConstraint() {
		return x509Certificate.getBasicConstraints();
	}

	/**
	 * The signature value of the certificate
	 * 
	 * @return the signature value
	 */
	public byte[] getSignature() {
		return x509Certificate.getSignature();
	}

	@Override
	protected TokenIdentifier buildTokenIdentifier() {
		return new CertificateTokenIdentifier(this);
	}

	@Override
	public String toString(String indentStr) {
		final StringBuilder out = new StringBuilder();
		out.append(indentStr).append("CertificateToken[\n");
		indentStr += "\t";

		out.append(indentStr).append("DSS Id              : ").append(getDSSIdAsString()).append('\n');
		out.append(indentStr).append("Identity Id         : ").append(getEntityKey()).append('\n');
		out.append(indentStr).append("Validity period     : ").append(x509Certificate.getNotBefore()).append(" - ").append(x509Certificate.getNotAfter())
				.append('\n');
		out.append(indentStr).append("Subject name        : ").append(getSubject().getCanonical()).append('\n');
		out.append(indentStr).append("Issuer subject name : ").append(getIssuer().getCanonical()).append('\n');
		out.append(indentStr).append("Serial Number       : ").append(getSerialNumber()).append('\n');
		out.append(indentStr).append("Signature algorithm : ").append(signatureAlgorithm == null ? "?" : signatureAlgorithm).append('\n');

		if (isSelfSigned()) {
			out.append(indentStr).append("[SELF-SIGNED]").append('\n');
		}

		indentStr = indentStr.substring(1);
		out.append(indentStr).append(']');
		return out.toString();
	}

}
