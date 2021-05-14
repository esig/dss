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

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.asn1.x509.ReasonFlags;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collection;
import java.util.Date;
import java.util.Objects;

/**
 * This class encapsulates all information related to the validity of a CRL. It
 * exposes the method {@code isValid} to check the validity.
 */
public class CRLValidity {

	/** Incorporates CRL binaries */
	private final CRLBinary crlBinary;

	/** distributionPoint [0] DistributionPointName OPTIONAL */
	private String url;

	/** onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE */
	private boolean onlyUserCerts;

	/** onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE */
	private boolean onlyCaCerts;

	/** onlySomeReasons [3] ReasonFlags OPTIONAL */
	private ReasonFlags onlySomeReasonFlags;

	/** indirectCRL [4] BOOLEAN DEFAULT FALSE */
	private boolean indirectCrl;

	/** onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE */
	private boolean onlyAttributeCerts;

	/** Defines if the signing certificate contains 'cRLSign' key usage */
	private boolean crlSignKeyUsage = false;

	/** Defines if the X509 Principal defined in CRL matches to the value of its issuer certificate */
	private boolean issuerX509PrincipalMatches = false;

	/** Defines if the signature is valid */
	private boolean signatureIntact = false;

	/** Contains a signature invalidity reason if the signature is invalid, null otherwise */
	private String signatureInvalidityReason;

	/** The used SignatureAlgorithm for the signature */
	private SignatureAlgorithm signatureAlgorithm;

	/** The issuer certificate */
	private CertificateToken issuerToken = null;

	/** Collection of critical extension OIDs */
	private Collection<String> criticalExtensionsOid;

	/** The 'expiredCertsOnCRL' date value */
	private Date expiredCertsOnCRL;

	/** The 'nextUpdate' date value */
	private Date nextUpdate;

	/** The 'thisUpdate' date value */
	private Date thisUpdate;
	
	/**
	 * Default constructor
	 *
	 * @param crlBinary {@link CRLBinary}
	 */	
	public CRLValidity(CRLBinary crlBinary) {
		Objects.requireNonNull(crlBinary, "CRLBinary cannot be null!");
		this.crlBinary = crlBinary;
	}

	/**
	 * Returns DER encoded binaries of the CRL
	 *
	 * @return DER encoded binaries
	 */
	public byte[] getDerEncoded() {
		return crlBinary.getBinaries();
	}

	/**
	 * Opens the InputStream with the CRL's binaries
	 *
	 * @return {@link InputStream}
	 */
	public InputStream toCRLInputStream() {
		return new ByteArrayInputStream(getDerEncoded());
	}

	/**
	 * Gets used SignatureAlgorithm
	 *
	 * @return {@link SignatureAlgorithm}
	 */
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	/**
	 * Sets used SignatureAlgorithm
	 *
	 * @param signatureAlgorithm {@link SignatureAlgorithm}
	 */
	public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	/**
	 * Gets the 'nextUpdate' field Date
	 *
	 * @return {@link Date}
	 */
	public Date getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * Sets the 'nextUpdate' field Date
	 *
	 * @param nextUpdate {@link Date}
	 */
	public void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	/**
	 * Gets the 'thisUpdate' field Date
	 *
	 * @return {@link Date}
	 */
	public Date getThisUpdate() {
		return thisUpdate;
	}

	/**
	 * Sets the 'thisUpdate' field Date
	 *
	 * @param thisUpdate {@link Date}
	 */
	public void setThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	/**
	 * Gets the 'expiredCertsOnCRL' field Date
	 *
	 * @return {@link Date}
	 */
	public Date getExpiredCertsOnCRL() {
		return expiredCertsOnCRL;
	}

	/**
	 * Sets the 'expiredCertsOnCRL' field Date
	 *
	 * @param expiredCertsOnCRL {@link Date}
	 */
	public void setExpiredCertsOnCRL(Date expiredCertsOnCRL) {
		this.expiredCertsOnCRL = expiredCertsOnCRL;
	}

	/**
	 * Returns if the issuer X509 Principal matches between one defined in CRL and
	 * its issuer certificate corresponding value
	 *
	 * @return TRUE if the issuer X509 Principal matches, FALSE otherwise
	 */
	public boolean isIssuerX509PrincipalMatches() {
		return issuerX509PrincipalMatches;
	}

	/**
	 * Sets if the issuer X509 Principal matches between one defined in CRL and
	 * its issuer certificate corresponding value
	 *
	 * @param issuerX509PrincipalMatches if the issuer X509 Principal matches
	 */
	public void setIssuerX509PrincipalMatches(boolean issuerX509PrincipalMatches) {
		this.issuerX509PrincipalMatches = issuerX509PrincipalMatches;
	}

	/**
	 * Gets if the signature value is valid
	 *
	 * @return TRUE if the signature is valid, FALSE otherwise
	 */
	public boolean isSignatureIntact() {
		return signatureIntact;
	}

	/**
	 * Sets if the signature value is valid
	 *
	 * @param signatureIntact if the signature value is valid
	 */
	public void setSignatureIntact(boolean signatureIntact) {
		this.signatureIntact = signatureIntact;
	}

	/**
	 * Gets if the issuer certificate has 'cRLSign' key usage
	 *
	 * @return TRUE if the issuer certificate has 'cRLSign' key usage, FALSE otherwise
	 */
	public boolean isCrlSignKeyUsage() {
		return crlSignKeyUsage;
	}

	/**
	 * Sets if the issuer certificate has 'cRLSign' key usage
	 *
	 * @param crlSignKeyUsage if the issuer certificate has 'cRLSign' key usage
	 */
	public void setCrlSignKeyUsage(boolean crlSignKeyUsage) {
		this.crlSignKeyUsage = crlSignKeyUsage;
	}

	/**
	 * Gets the issuer certificateToken
	 *
	 * @return {@link CertificateToken}
	 */
	public CertificateToken getIssuerToken() {
		return issuerToken;
	}

	/**
	 * Sets the issuer certificateToken
	 *
	 * @param issuerToken {@link CertificateToken}
	 */
	public void setIssuerToken(CertificateToken issuerToken) {
		this.issuerToken = issuerToken;
	}

	/**
	 * Gets signature invalidity reason if signature is invalid
	 *
	 * @return signature invalidity reason {@link String}, null for a valid signatureValue
	 */
	public String getSignatureInvalidityReason() {
		return signatureInvalidityReason;
	}

	/**
	 * Sets signature invalidity reason
	 *
	 * @param signatureInvalidityReason {@link String}
	 */
	public void setSignatureInvalidityReason(String signatureInvalidityReason) {
		this.signatureInvalidityReason = signatureInvalidityReason;
	}

	/**
	 * Gets distributionPoint url
	 * ...
	 * distributionPoint [0] DistributionPointName OPTIONAL
	 * ...
	 *
	 * @return {@link String} distributionPoint url
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * Sets distributionPoint url
	 * ...
	 * distributionPoint [0] DistributionPointName OPTIONAL
	 * ...
	 *
	 * @param url {@link String} distributionPoint url
	 */
	public void setUrl(String url) {
		this.url = url;
	}

	/**
	 * Sets 'onlyContainsUserCerts' value
	 * ...
	 * onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE
	 * ...
	 *
	 * @param onlyUserCerts 'onlyContainsUserCerts' value
	 */
	public void setOnlyUserCerts(boolean onlyUserCerts) {
		this.onlyUserCerts = onlyUserCerts;
	}

	/**
	 * Sets 'onlyContainsCACerts' value
	 * ...
	 * onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE
	 * ...
	 *
	 * @param onlyCaCerts 'onlyContainsCACerts' value
	 */
	public void setOnlyCaCerts(boolean onlyCaCerts) {
		this.onlyCaCerts = onlyCaCerts;
	}

	/**
	 * Sets 'onlySomeReasons' value
	 * ...
	 * onlySomeReasons [3] ReasonFlags OPTIONAL
	 * ...
	 *
	 * @param reasonFlags 'onlySomeReasons' value
	 */
	public void setReasonFlags(ReasonFlags reasonFlags) {
		this.onlySomeReasonFlags = reasonFlags;
	}

	/**
	 * Sets 'indirectCRL' value
	 * ...
	 * indirectCRL [4] BOOLEAN DEFAULT FALSE
	 * ...
	 *
	 * @param indirectCrl 'indirectCRL' value
	 */
	public void setIndirectCrl(boolean indirectCrl) {
		this.indirectCrl = indirectCrl;
	}

	/**
	 * Sets 'onlyContainsAttributeCerts' value
	 * ...
	 * onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
	 * ...
	 *
	 * @param onlyAttributeCerts 'onlyContainsAttributeCerts' value
	 */
	public void setOnlyAttributeCerts(boolean onlyAttributeCerts) {
		this.onlyAttributeCerts = onlyAttributeCerts;
	}

	/**
	 * Checks if the collection of critical extension OIDs is not empty
	 *
	 * @return TRUE if the collection of critical extension OIDs is not empty, FALSE if empty
	 */
	public boolean areCriticalExtensionsOidNotEmpty() {
		return criticalExtensionsOid != null && !criticalExtensionsOid.isEmpty();
	}

	/**
	 * Sets a collection of critical extension OIDs
	 *
	 * @param criticalExtensionsOid a collection of {@link String} critical extension OIDs
	 */
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

	/**
	 * Checks if the critical extensions are unknown
	 *
	 * @return TRUE if the critical extensions are unknown, FALSE otherwise
	 */
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
