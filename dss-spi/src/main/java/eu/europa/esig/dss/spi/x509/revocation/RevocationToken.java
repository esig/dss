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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.revocation.Revocation;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Represents a revocation data token
 *
 * @param <R> {@code Revocation}
 */
@SuppressWarnings("serial")
public abstract class RevocationToken<R extends Revocation> extends Token {

	/**
	 * Related {@link CertificateToken} to this revocation object
	 */
	protected CertificateToken relatedCertificate;

	/**
	 * The URL which was used to obtain the revocation data (online).
	 */
	protected String sourceURL;

	/**
	 * The external origin (ONLINE or CACHED)
	 */
	protected RevocationOrigin externalOrigin;

	/**
	 * Contains the revocation status of the token.
	 */
	protected CertificateStatus status;

	/**
	 * Represents the production date of the OCSP response or the thisUpdate in case of CRL.
	 */
	protected Date productionDate;

	/**
	 * Represents the this update date of the CRL.
	 */
	protected Date thisUpdate;

	/**
	 * Represents the next update date of the CRL or null for OCSP response.
	 */
	protected Date nextUpdate;

	/**
	 * Represents the revocation date from an X509CRLEntry or from an BasicOCSPResp (if the related certificate is
	 * revoked)
	 */
	protected Date revocationDate;

	/**
	 * Sequential number of revocation token (applicable for CRLs only)
	 */
	protected BigInteger crlNumber;

	/**
	 * expired-certs-on-crl time extension
	 */
	protected Date expiredCertsOnCRL;

	/**
	 * archive-cut-off time extension
	 */
	protected Date archiveCutOff;

	/**
	 * Represents if the certHash extension from an OCSP Response is present (optional)
	 */
	protected boolean certHashPresent = false;

	/**
	 * Represents if the certHash extension from an OCSP Response is match with the related certificate's hash (optional)
	 */
	protected boolean certHashMatch = false;

	/**
	 * The reason of the revocation.
	 */
	protected RevocationReason reason;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected RevocationToken() {
	}
	
	/**
	 * Returns the Revocation Token type (CRL or OCSP)
	 * 
	 * @return {@link RevocationType} of the token
	 */
	public abstract RevocationType getRevocationType();

	/**
	 * Returns a certificate token the current revocation data has been issued for
	 *
	 * @return {@link CertificateToken}
	 */
	public CertificateToken getRelatedCertificate() {
		return relatedCertificate;
	}

	/**
	 * Gets DSS String Id of the related certificate
	 *
	 * @return {@link String}
	 */
	public String getRelatedCertificateId() {
		if (relatedCertificate != null) {
			return relatedCertificate.getDSSIdAsString();
		}
		return null;
	}
	
	/**
	 * Returns issuer {@code CertificateToken}
	 * 
	 * @return issuer {@link CertificateToken}
	 */
	public abstract CertificateToken getIssuerCertificateToken();

	/**
	 * Returns the URL of the source (if available)
	 * 
	 * @return URL of the CRL/OCSP Server (if available)
	 */
	public String getSourceURL() {
		return sourceURL;
	}

	/**
	 * This sets the revocation data source URL. It is only used in case of
	 * {@code OnlineSource}.
	 *
	 * @param sourceURL
	 *            the URL which was used to retrieve this CRL
	 */
	public void setSourceURL(final String sourceURL) {
		this.sourceURL = sourceURL;
	}

	/**
	 * Returns the certificate status
	 * 
	 * @return the certificate status
	 */
	public CertificateStatus getStatus() {
		return status;
	}

	/**
	 * Returns the generation time of the current revocation data (when it was signed)
	 * 
	 * @return the production time of the current revocation data
	 */
	public Date getProductionDate() {
		return productionDate;
	}

	@Override
	public Date getCreationDate() {
		return productionDate;
	}

	/**
	 * Returns the date of the this update
	 *
	 * @return the this update date
	 */
	public Date getThisUpdate() {
		return thisUpdate;
	}

	/**
	 * Returns the date of the next update
	 * 
	 * @return the next update date
	 */
	public Date getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * Returns the revocation date (if the token has been revoked)
	 * 
	 * @return the revocation date or null
	 */
	public Date getRevocationDate() {
		return revocationDate;
	}

	/**
	 * Gets sequential number of the revocation token, when present (CRL only)
	 *
	 * @return {@link BigInteger}
	 */
	public BigInteger getCRLNumber() {
		return crlNumber;
	}

	/**
	 * Returns the expiredCertsOnCRL date (from CRL)
	 * 
	 * @return the expiredCertsOnCRL date value from a CRL or null
	 */
	public Date getExpiredCertsOnCRL() {
		return expiredCertsOnCRL;
	}

	/**
	 * Returns the archiveCutOff date (from an OCSP Response)
	 * 
	 * @return the archiveCutOff date or null
	 */
	public Date getArchiveCutOff() {
		return archiveCutOff;
	}

	/**
	 * Returns TRUE if the certHash extension (from an OCSP Response) is present
	 * @return the TRUE if certHash is present, FALSE otherwise
	 */
	public boolean isCertHashPresent() {
		return certHashPresent;
	}

	/**
	 * Returns TRUE if the certHash extension (from an OCSP Response) is match to the hash of related certificate token
	 * @return the TRUE if certHash is match, FALSE otherwise
	 */
	public boolean isCertHashMatch() {
		return certHashMatch;
	}

	/**
	 * Returns the revocation reason (if the token has been revoked)
	 * 
	 * @return the revocation reason or null
	 */
	public RevocationReason getReason() {
		return reason;
	}
	
	/**	
	 * Returns a source of embedded into a revocation token certificates
	 * 
	 * @return {@link RevocationCertificateSource}
	 */
	public abstract RevocationCertificateSource getCertificateSource();

	/**
	 * Returns a collection of embedded certificates.
	 * NOTE: returns empty collection for CRL.
	 *
	 * @return a list of {@code CertificateToken}s
	 */
	public abstract List<CertificateToken> getCertificates();

	/**
	 * Sets the external origin
	 *
	 * @param origin {@link RevocationOrigin}
	 */
	public void setExternalOrigin(RevocationOrigin origin) {
		Objects.requireNonNull(origin, "The origin is null");
		if (origin.isInternalOrigin()) {
			throw new IllegalArgumentException("Only external are allowed");
		}
		this.externalOrigin = origin;
	}

	/**
	 * Gets the external origin
	 *
	 * @return {@link RevocationOrigin}
	 */
	public RevocationOrigin getExternalOrigin() {
		return externalOrigin;
	}

	/**
	 * This method returns true if the token was not collected from an external
	 * resource (online or jdbc)
	 * 
	 * @return true if the token comes from a signature/timestamp
	 */
	public boolean isInternal() {
		return externalOrigin == null;
	}

	@Override
	protected TokenIdentifier buildTokenIdentifier() {
		return new RevocationTokenIdentifier(this);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + getDSSId().hashCode();
		result = prime * result + ((relatedCertificate == null) ? 0 : relatedCertificate.getDSSIdAsString().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RevocationToken<?> other = (RevocationToken<?>) obj;
		if (!getDSSId().equals(other.getDSSId())) {
			return false;
		}
		if (relatedCertificate == null) {
			return other.relatedCertificate == null;
		} else return relatedCertificate.equals(other.relatedCertificate);
	}

}
