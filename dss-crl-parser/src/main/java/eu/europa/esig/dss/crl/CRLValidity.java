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
package eu.europa.esig.dss.crl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collection;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.asn1.x509.ReasonFlags;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * This class encapsulates all information related to the validity of a CRL. It
 * exposes the method {@code isValid} to check the validity.
 */
public class CRLValidity {
	
	protected CRLBinary crlBinary;
	
	private boolean indirectCrl;
	private boolean onlyAttributeCerts;
	private boolean onlyCaCerts;
	private boolean onlyUserCerts;
	private boolean crlSignKeyUsage = false;
	private boolean issuerX509PrincipalMatches = false;
	private boolean signatureIntact = false;
	private CertificateToken issuerToken = null;
	private Collection<String> criticalExtensionsOid;
	private Date expiredCertsOnCRL;
	private Date nextUpdate;
	private Date thisUpdate;
	private ReasonFlags onlySomeReasonFlags;
	private SignatureAlgorithm signatureAlgorithm;
	private String key;
	private String signatureInvalidityReason;
	private String url;
	
	/**
	 * Default constructor
	 */	
	public CRLValidity(CRLBinary crlBinary) {
		Objects.requireNonNull(crlBinary, "CRLBinary cannot be null!");
		this.crlBinary = crlBinary;
	}

	public byte[] getDerEncoded() {
		return crlBinary.getBinaries();
	}

	public InputStream toCRLInputStream() {
		return new ByteArrayInputStream(getDerEncoded());
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public Date getNextUpdate() {
		return nextUpdate;
	}

	public void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	public Date getThisUpdate() {
		return thisUpdate;
	}

	public void setThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	public Date getExpiredCertsOnCRL() {
		return expiredCertsOnCRL;
	}

	public void setExpiredCertsOnCRL(Date expiredCertsOnCRL) {
		this.expiredCertsOnCRL = expiredCertsOnCRL;
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

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}
	
	public void setOnlyAttributeCerts(boolean onlyAttributeCerts) {
		this.onlyAttributeCerts = onlyAttributeCerts;
	}
	
	public void setOnlyCaCerts(boolean onlyCaCerts) {
		this.onlyCaCerts = onlyCaCerts;
	}
	
	public void setOnlyUserCerts(boolean onlyUserCerts) {
		this.onlyUserCerts = onlyUserCerts;
	}
	
	public void setIndirectCrl(boolean indirectCrl) {
		this.indirectCrl = indirectCrl;
	}
	
	public void setReasonFlags(ReasonFlags reasonFlags) {
		this.onlySomeReasonFlags = reasonFlags;
	}
	
	public void setCriticalExtensionsOid(Collection<String> criticalExtensionsOid) {
		this.criticalExtensionsOid = criticalExtensionsOid;
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
	public boolean isValid() {
		return issuerX509PrincipalMatches && signatureIntact && crlSignKeyUsage && !isUnknownCriticalExtension();
	}
	
	public boolean areCriticalExtensionsOidNotEmpty() {
		return criticalExtensionsOid != null && !criticalExtensionsOid.isEmpty();
	}
	
	public boolean isUnknownCriticalExtension() {
		return areCriticalExtensionsOidNotEmpty() && 
					((onlyAttributeCerts && onlyCaCerts && onlyUserCerts && indirectCrl) || (onlySomeReasonFlags != null) || (url == null));
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((crlBinary == null) ? 0 : crlBinary.hashCode());
		result = prime * result + ((issuerToken == null) ? 0 : issuerToken.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CRLValidity other = (CRLValidity) obj;
		if (crlBinary == null) {
			if (other.crlBinary != null) {
				return false;
			}
		} else if (!crlBinary.equals(other.crlBinary)) {
			return false;
		}
		if (issuerToken == null) {
			if (other.issuerToken != null) {
				return false;
			}
		} else if (!issuerToken.equals(other.issuerToken)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "CRLValidity{" + "DSS ID=" + crlBinary.asXmlId() + ", issuerX509PrincipalMatches=" + issuerX509PrincipalMatches + 
				", signatureIntact=" + signatureIntact + ", crlSignKeyUsage=" + crlSignKeyUsage + ", unknownCriticalExtension=" 
				+ isUnknownCriticalExtension() + ", issuerToken=" + issuerToken + ", signatureInvalidityReason='"
				+ signatureInvalidityReason + '\'' + '}';
	}
}
