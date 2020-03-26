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
package eu.europa.esig.dss.validation;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Objects;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateIdentifier;

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
	private CertificateIdentifier certificateIdentifier;
	/* CMS Signer id */
	private boolean signerIdMatch;
	private boolean digestPresent;
	private boolean digestEqual;
	private boolean attributePresent;
	private boolean serialNumberEqual;
	private boolean distinguishedNameEqual;

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
	 * @param certificateIdentifier the {@code CertificateIdentifier} associated to
	 *                              the signing certificate
	 */
	public CertificateValidity(final CertificateIdentifier certificateIdentifier) {
		Objects.requireNonNull(certificateIdentifier, "CertificateIdentifier cannot be null!");
		this.certificateIdentifier = certificateIdentifier;
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
	 * Returns the associated {@link CertificateIdentifier}
	 * NOTE: can return null
	 * 
	 * @return {@link CertificateIdentifier}
	 */
	public CertificateIdentifier getSignerInfo() {
		if (certificateToken == null) {
			return certificateIdentifier;
		}
		CertificateIdentifier certificateIdentifierFromCert = new CertificateIdentifier();
		certificateIdentifierFromCert.setIssuerName(certificateToken.getIssuerX500Principal());
		certificateIdentifierFromCert.setSerialNumber(certificateToken.getSerialNumber());
		return certificateIdentifierFromCert;
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
	 * @return
	 */
	public boolean isAttributePresent() {
		return attributePresent;
	}

	public void setAttributePresent(boolean attributePresent) {
		this.attributePresent = attributePresent;
	}

	public boolean isSerialNumberEqual() {
		return serialNumberEqual;
	}

	public void setSerialNumberEqual(final boolean serialNumberEqual) {
		this.serialNumberEqual = serialNumberEqual;
	}

	public void setDistinguishedNameEqual(final boolean distinguishedNameEqual) {
		this.distinguishedNameEqual = distinguishedNameEqual;
	}

	public boolean isDistinguishedNameEqual() {
		return distinguishedNameEqual;
	}

	/**
	 * This method returns {@code true} if the certificate digest or
	 * IssuerSerial/issuerAndSerialNumber match or the certificate is signed.
	 *
	 * @return {@code true} if the certificate digest matches.
	 */
	public boolean isValid() {
		return isDigestEqual() || (isDistinguishedNameEqual() && isSerialNumberEqual());
	}

}
