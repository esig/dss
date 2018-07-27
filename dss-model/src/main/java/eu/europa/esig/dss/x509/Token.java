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
package eu.europa.esig.dss.x509;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.TokenIdentifier;

/**
 * This is the base class for the different types of tokens (certificate, OCSP,
 * CRL, Timestamp) used in the process of signature validation.
 */
@SuppressWarnings("serial")
public abstract class Token implements Serializable {

	private String dssId;

	/**
	 * The token identifier to avoid to compute more than one time the digest value
	 */
	private TokenIdentifier tokenIdentifier;

	/**
	 * The publicKey of the signed certificate(s)
	 */
	protected PublicKey publicKeyOfTheSigner;

	/**
	 * Indicates the token signature is valid.
	 */
	protected boolean signatureValid = false;

	/**
	 * Indicates the token signature invalidity reason.
	 */
	protected String signatureInvalidityReason = "";

	/**
	 * The algorithm that was used to sign the token.
	 */
	protected SignatureAlgorithm signatureAlgorithm;

	/**
	 * Extra information collected during the validation process.
	 */
	protected TokenValidationExtraInfo extraInfo;

	private Map<DigestAlgorithm, byte[]> digests = new HashMap<DigestAlgorithm, byte[]>();

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || !(obj instanceof Token)) {
			return false;
		}

		Token o2 = (Token) obj;
		return getDSSId().equals(o2.getDSSId());
	}

	@Override
	public int hashCode() {
		return getDSSId().hashCode();
	}

	/**
	 * Checks if the certificate is provided by the trusted list. For all tokens
	 * different from CertificateToken this method always returns false. This method
	 * was introduced in order to manage in a uniform manner the different tokens.
	 *
	 * @return true if the token is trusted
	 */
	public boolean isTrusted() {
		return false;
	}

	/**
	 * Checks if the certificate is self-signed. For all tokens different from
	 * CertificateToken this method always returns false. This method was introduced
	 * in order to manage in a uniform manner the different tokens.
	 *
	 * @return true if the token is self-signed
	 */
	public boolean isSelfSigned() {
		return false;
	}

	/**
	 * Returns a DSS unique token identifier.
	 * 
	 * @return an instance of TokenIdentifier
	 */
	public TokenIdentifier getDSSId() {
		if (tokenIdentifier == null) {
			tokenIdentifier = new TokenIdentifier(this);
		}
		return tokenIdentifier;
	}

	/**
	 * Returns a string representation of the unique DSS token identifier.
	 * 
	 * @return the unique string for the token
	 */
	public String getDSSIdAsString() {
		if (dssId == null) {
			dssId = getDSSId().asXmlId();
		}
		return dssId;
	}

	/**
	 * Checks if the token is signed by the public key given in the parameter. *
	 * 
	 * @param publicKey
	 *                  the public key to be tested
	 * @return true if this token is signed by the given certificate token
	 */
	public boolean isSignedBy(PublicKey publicKey) {
		if (publicKeyOfTheSigner != null) {
			return publicKeyOfTheSigner.equals(publicKey);
		} else if (checkIsSignedBy(publicKey)) {
			if (!isSelfSigned()) {
				this.publicKeyOfTheSigner = publicKey;
			}
			return true;
		}
		return false;
	}

	protected abstract boolean checkIsSignedBy(PublicKey publicKey);

	/**
	 * Returns the {@code X500Principal} of the certificate which was used to sign
	 * this token.
	 *
	 * @return the issuer's {@code X500Principal}
	 */
	public abstract X500Principal getIssuerX500Principal();

	/**
	 * Returns the additional information gathered during the validation process.
	 *
	 * @return additional validation information
	 */
	public List<String> getValidationInfo() {
		return extraInfo.getValidationInfo();
	}

	/**
	 * This method returns the DSS abbreviation of the token. It is used for
	 * debugging purpose.
	 *
	 * @return an abbreviation for the certificate
	 */
	public String getAbbreviation() {
		return "?";
	}

	/**
	 * Returns the algorithm that was used to sign the token (ex:
	 * SHA1WithRSAEncryption, SHA1withRSA...).
	 *
	 * @return the used signature algorithm to sign this token
	 */
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	/**
	 * Indicates if the token's signature is intact. For each kind of token the
	 * method isSignedBy(CertificateToken) must be called to set this flag. Except
	 * if the token is trusted: the signature signature is assumed to be valid.
	 *
	 * @return true if the signature is valid or trusted
	 */
	public boolean isSignatureValid() {
		return isTrusted() || signatureValid;
	}

	/**
	 * This method returns the public key of the token signer
	 * 
	 * @return the public key which signed this token
	 */
	public PublicKey getPublicKeyOfTheSigner() {
		return publicKeyOfTheSigner;
	}

	/**
	 * Returns the object managing the validation extra info.
	 *
	 * @return additional validation information
	 */
	public TokenValidationExtraInfo extraInfo() {
		return extraInfo;
	}

	/**
	 * Returns a string representation of the token.
	 *
	 * @param indentStr
	 *                  the indentation to use
	 * @return string representation of the token
	 */
	public abstract String toString(String indentStr);

	@Override
	public String toString() {
		return toString("");
	}

	/**
	 * Returns the encoded form of the wrapped token.
	 *
	 * @return the encoded form of the wrapped token
	 */
	public abstract byte[] getEncoded();

	/**
	 * Returns the digest value of the wrapped token
	 * 
	 * @param digestAlgorithm
	 *                        the requested digest algorithm
	 * @return the digest value in binaries
	 */
	public byte[] getDigest(DigestAlgorithm digestAlgorithm) {
		byte[] digestValue = digests.get(digestAlgorithm);
		if (digestValue == null) {
			digestValue = getDigest(digestAlgorithm, getEncoded());
			digests.put(digestAlgorithm, digestValue);
		}
		return digestValue;
	}

	protected byte[] getDigest(DigestAlgorithm digestAlgorithm, byte[] toBeDigested) {
		try {
			MessageDigest md = MessageDigest.getInstance(digestAlgorithm.getJavaName());
			return md.digest(toBeDigested);
		} catch (Exception e) {
			throw new DSSException("Unable to compute digest with algo " + digestAlgorithm, e);
		}
	}

}
