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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Objects;

/**
 * This class stores the information about the validity of the signing certificate.
 */
public class CertificateValidity implements Serializable {

	private static final long serialVersionUID = -8840096915238342503L;
	
	/**
	 * This field is used when only the public key is available (non AdES signature)
	 */
	private PublicKey publicKey;
	
	private CertificateToken certificateToken;
	
	private SignerIdentifier signerIdentifier;
	
	/** CMS Signer id */
	private boolean signerIdMatch;

	/** Digest parameters */
	private boolean digestPresent;
	private boolean digestEqual;

	/** Issuer Serial */
	private boolean issuerSerialPresent;
	private boolean serialNumberEqual;
	private boolean distinguishedNameEqual;
	
	/** OCSP Responder Id */
	private boolean responderIdPresent;
	private boolean responderIdMatch;

	/**
	 * This constructor create an object containing all information concerning the validity of a candidate for the
	 * signing certificate.
	 *
	 * @param certificateToken
	 *            the candidate for the signing certificate
	 */
	public CertificateValidity(final CertificateToken certificateToken) {
		Objects.requireNonNull(certificateToken, "CertificateToken cannot be null!");
		this.certificateToken = certificateToken;
	}

	/**
	 * This constructor create an object containing all information concerning the validity of a candidate for the
	 * signing certificate which is based only on the {@code PublicKey}. To be used in case of a non AdES signature.
	 *
	 * @param publicKey
	 *            the {@code PublicKey} associated to the signing certificate.
	 */
	public CertificateValidity(final PublicKey publicKey) {
		Objects.requireNonNull(publicKey, "PublicKey cannot be null!");
		this.publicKey = publicKey;
	}
	
	/**
	 * This constructor create an object containing all information concerning the
	 * validity of a candidate for the signing certificate which is based only on
	 * the {@code CertificateIdentifier}. To be used in case of a non AdES
	 * signature.
	 *
	 * @param signerIdentifier the {@code CertificateIdentifier} associated to
	 *                              the signing certificate
	 */
	public CertificateValidity(final SignerIdentifier signerIdentifier) {
		Objects.requireNonNull(signerIdentifier, "CertificateIdentifier cannot be null!");
		this.signerIdentifier = signerIdentifier;
	}

	/**
	 * If the {@code certificateToken} is not null then the associated {@code PublicKey} will be returned otherwise the
	 * provided {@code publicKey} is returned.
	 * NOTE: can return null
	 *
	 * @return the public key associated with this instance.
	 */
	public PublicKey getPublicKey() {
		return certificateToken == null ? publicKey : certificateToken.getPublicKey();
	}
	
	/**
	 * Returns the associated {@link SignerIdentifier}
	 * NOTE: can return null
	 * 
	 * @return {@link SignerIdentifier}
	 */
	public SignerIdentifier getSignerInfo() {
		if (certificateToken == null) {
			return signerIdentifier;
		}
		SignerIdentifier signerIdentifierFromCert = new SignerIdentifier();
		signerIdentifierFromCert.setIssuerName(certificateToken.getIssuerX500Principal());
		signerIdentifierFromCert.setSerialNumber(certificateToken.getSerialNumber());
		return signerIdentifierFromCert;
	}

	public CertificateToken getCertificateToken() {
		return certificateToken;
	}

	public boolean isSignerIdMatch() {
		return signerIdMatch;
	}

	public void setSignerIdMatch(boolean signerIdMatch) {
		this.signerIdMatch = signerIdMatch;
	}

	public boolean isDigestPresent() {
		return digestPresent;
	}

	public void setDigestPresent(boolean digestPresent) {
		this.digestPresent = digestPresent;
	}

	public boolean isDigestEqual() {
		return digestEqual;
	}

	public void setDigestEqual(final boolean digestEqual) {
		this.digestEqual = digestEqual;
	}

	/**
	 * Indicates if the IssuerSerial (issuerAndSerialNumber) is present in the signature.
	 *
	 * @return TRUE if the IssuerSerial is present
	 */
	public boolean isIssuerSerialPresent() {
		return issuerSerialPresent;
	}

	/**
	 * Sets if the IssuerSerial is present
	 *
	 * @param issuerSerialPresent TRUE if the IssuerSerial is present, FALSE otherwise
	 */
	public void setIssuerSerialPresent(boolean issuerSerialPresent) {
		this.issuerSerialPresent = issuerSerialPresent;
	}

	/**
	 * Indicates if the SerialNumber equals
	 *
	 * @return TRUE if the SerialNumber equals
	 */
	public boolean isSerialNumberEqual() {
		return serialNumberEqual;
	}

	/**
	 * Sets if the serial number matches
	 *
	 * @param serialNumberEqual if the serial number matches
	 */
	public void setSerialNumberEqual(final boolean serialNumberEqual) {
		this.serialNumberEqual = serialNumberEqual;
	}

	/**
	 * Gets if the distinguished name equals
	 *
	 * @return TRUE if the distinguished name equals, FALSE otherwise
	 */
	public boolean isDistinguishedNameEqual() {
		return distinguishedNameEqual;
	}

	/**
	 * Sets if the distinguished name equals
	 *
	 * @param distinguishedNameEqual if the distinguished name equals
	 */
	public void setDistinguishedNameEqual(final boolean distinguishedNameEqual) {
		this.distinguishedNameEqual = distinguishedNameEqual;
	}

	/**
	 * Gets if the ResponderId is present
	 *
	 * @return TRUE if the ResponderId is present, FALSE otherwise
	 */
	public boolean isResponderIdPresent() {
		return responderIdPresent;
	}

	/**
	 * Sets if the ResponderId is present
	 *
	 * @param responderIdPresent if the ResponderId is present
	 */
	public void setResponderIdPresent(boolean responderIdPresent) {
		this.responderIdPresent = responderIdPresent;
	}

	/**
	 * Gets if the Responder Id matches
	 *
	 * @return TRUE if the Responder Id matches, FALSE otherwise
	 */
	public boolean isResponderIdMatch() {
		return responderIdMatch;
	}

	/**
	 * Sets if the ResponderId matches
	 *
	 * @param responderIdMatch if the ResponderId matches
	 */
	public void setResponderIdMatch(boolean responderIdMatch) {
		this.responderIdMatch = responderIdMatch;
	}

	/**
	 * This method returns {@code true} if the certificate digest or
	 * IssuerSerial/issuerAndSerialNumber match or the certificate is signed.
	 *
	 * @return {@code true} if the certificate digest matches.
	 */
	public boolean isValid() {
		return isDigestEqual() || (isDistinguishedNameEqual() && isSerialNumberEqual()) || isResponderIdMatch();
	}

}
