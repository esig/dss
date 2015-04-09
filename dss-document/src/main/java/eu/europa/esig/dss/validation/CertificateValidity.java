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

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class stores the information about the validity of the signing certificate.
 */
public class CertificateValidity implements Serializable {

	/**
	 * This field is used when only the public key is available (non AdES signature)
	 */
	private PublicKey publicKey;
	private CertificateToken certificateToken;
	private boolean digestPresent;
	private boolean digestEqual;
	private boolean attributePresent;
	private boolean serialNumberEqual;
	private boolean distinguishedNameEqual;

	/**
	 * Indicates what element encapsulating the signed certificate has been signed.
	 */
	private String signed;
	private String digest;
	private DigestAlgorithm digestAlgorithm;

	/**
	 * This constructor create an object containing all information concerning the validity of a candidate for the signing certificate.
	 *
	 * @param certificateToken the candidate for the signing certificate
	 */
	public CertificateValidity(final CertificateToken certificateToken) {

		this.certificateToken = certificateToken;
	}

	/**
	 * This constructor create an object containing all information concerning the validity of a candidate for the signing certificate which is based only on the {@code
	 * PublicKey}. To be used in case of a non AdES signature.
	 *
	 * @param publicKey the {@code PublicKey} associated to the signing certificate.
	 */
	public CertificateValidity(final PublicKey publicKey) {

		this.publicKey = publicKey;
	}

	/**
	 * If the {@code certificateToken} is not null then the associated {@code PublicKey} will be returned otherwise the provided {@code publicKey} is returned.
	 *
	 * @return the public key associated with this instance.
	 */
	public PublicKey getPublicKey() {

		return certificateToken == null ? publicKey : certificateToken.getCertificate().getPublicKey();
	}

	public CertificateToken getCertificateToken() {
		return certificateToken;
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
	 * @return returns the signed element: X509Certificate, X509Data or KeyInfo. {@code null} if there is no signed element
	 */
	public String getSigned() {
		return signed;
	}

	/**
	 * Allows to set the signed element: X509Certificate, X509Data or KeyInfo
	 *
	 * @param signed indicates the element which was signed
	 */
	public void setSigned(final String signed) {

		if (!XPathQueryHolder.XMLE_X509CERTIFICATE.equals(signed) && !XPathQueryHolder.XMLE_X509DATA.equals(signed) && !XPathQueryHolder.XMLE_KEYINFO.equals(signed)) {
			throw new DSSException("The signed element should be one of the following: X509Certificate, X509Data or KeyInfo!");
		}
		this.signed = signed;
	}

	/**
	 * This method returns {@code true} if the certificate digest or IssuerSerial/issuerAndSerialNumber match or the certificate is signed. The signed reference is checked
	 * following the validation policy.
	 *
	 * @return {@code true} if the certificate digest matches.
	 */
	public boolean isValid() {

		final boolean valid = isDigestEqual() || (isDistinguishedNameEqual() && isSerialNumberEqual()) || StringUtils.isNotEmpty(getSigned());
		return valid;
	}

	public void setDigest(final String digest) {
		this.digest = digest;
	}

	public String getDigest() {
		return digest;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}
}
