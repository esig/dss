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
package eu.europa.esig.dss.x509.crl;

import java.security.cert.X509CRL;

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class encapsulates all information related to the validity of a CRL. It
 * exposes the method {@code isValid} to check the validity.
 */
public class CRLValidity {

	private X509CRL x509CRL = null;
	private boolean issuerX509PrincipalMatches = false;
	private boolean signatureIntact = false;
	private boolean crlSignKeyUsage = false;
	private boolean unknownCriticalExtension = true;
	private CertificateToken issuerToken = null;
	private String signatureInvalidityReason = "";

	public X509CRL getX509CRL() {
		return x509CRL;
	}

	public void setX509CRL(X509CRL x509crl) {
		x509CRL = x509crl;
	}

	public boolean isIssuerX509PrincipalMatches() {
		return issuerX509PrincipalMatches;
	}

	public void setIssuerX509PrincipalMatches(boolean issuerX509PrincipalMatches) {
		this.issuerX509PrincipalMatches = issuerX509PrincipalMatches;
	}

	public boolean isSignatureIntact() {
		return signatureIntact;
	}

	public void setSignatureIntact(boolean signatureIntact) {
		this.signatureIntact = signatureIntact;
	}

	public boolean isCrlSignKeyUsage() {
		return crlSignKeyUsage;
	}

	public void setCrlSignKeyUsage(boolean crlSignKeyUsage) {
		this.crlSignKeyUsage = crlSignKeyUsage;
	}

	public boolean isUnknownCriticalExtension() {
		return unknownCriticalExtension;
	}

	public void setUnknownCriticalExtension(boolean unknownCriticalExtension) {
		this.unknownCriticalExtension = unknownCriticalExtension;
	}

	public CertificateToken getIssuerToken() {
		return issuerToken;
	}

	public void setIssuerToken(CertificateToken issuerToken) {
		this.issuerToken = issuerToken;
	}

	public String getSignatureInvalidityReason() {
		return signatureInvalidityReason;
	}

	public void setSignatureInvalidityReason(String signatureInvalidityReason) {
		this.signatureInvalidityReason = signatureInvalidityReason;
	}

	/**
	 * This method indicates if the CRL is valid. To be valid the CRL must full
	 * fill the following requirements:
	 *
	 * - its signature must be valid, - the issuer of the certificate for which
	 * the CRL is used must match the CRL signing certificate and - the
	 * mandatory key usage must be present.
	 *
	 * @return {@code true} if the CRL is valid {@code false} otherwise.
	 */
	boolean isValid() {

		return issuerX509PrincipalMatches && signatureIntact && crlSignKeyUsage && !unknownCriticalExtension;
	}

	@Override
	public String toString() {
		return "CRLValidity{" + "issuerX509PrincipalMatches=" + issuerX509PrincipalMatches + ", signatureIntact=" + signatureIntact
				+ ", crlSignKeyUsage=" + crlSignKeyUsage + ", unknownCriticalExtension=" + unknownCriticalExtension + ", issuerToken=" + issuerToken
				+ ", signatureInvalidityReason='" + signatureInvalidityReason + '\'' + '}';
	}
}
