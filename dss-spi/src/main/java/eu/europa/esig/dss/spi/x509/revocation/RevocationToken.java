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
package eu.europa.esig.dss.spi.x509.revocation;

import java.util.Date;
import java.util.Set;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.utils.Utils;

@SuppressWarnings("serial")
public abstract class RevocationToken extends Token {

	/**
	 * Related {@link CertificateToken} to this revocation object
	 */
	protected CertificateToken relatedCertificate;
	
	/**
	 * An identifier referencing a CRL or OCSP response has been used for determining the revocation status.
	 */
	protected RevocationType revocationType;

	/**
	 * Origins of the revocation data (signature or external)
	 */
	private Set<RevocationOrigin> origins;

	/**
	 * The URL which was used to obtain the revocation data (online).
	 */
	protected String sourceURL;

	/**
	 * This boolean shows if the online resource is available
	 */
	protected boolean available;

	/**
	 * Contains the revocation status of the token. True if is not revoked, false if is revoked or null if unknown.
	 */
	protected Boolean status;

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

	protected Date expiredCertsOnCRL;

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
	 * Revocation Token Key, used for {@link RevocationToken} identification (i.e. id in DB)
	 */
	protected String revocationTokenKey;
	
	public RevocationType getRevocationType() {
		return revocationType;
	}

	public String getRelatedCertificateID() {
		if (relatedCertificate != null) {
			return relatedCertificate.getDSSIdAsString();
		}
		return null;
	}

	public void setRelatedCertificate(CertificateToken relatedCertificate) {
		this.relatedCertificate = relatedCertificate;
	}

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
	 * Returns the revocation origin (the signature itself or else)
	 * 
	 * @return the origin of this revocation data
	 */
	public Set<RevocationOrigin> getOrigins() {
		return origins;
	}
	
	/**
	 * Returns first found origin from the set of {@code RevocationOrigin}s
	 * @return {@link RevocationOrigin}
	 */
	public RevocationOrigin getFirstOrigin() {
		if (Utils.isCollectionNotEmpty(origins)) {
			return origins.iterator().next();
		}
		return null;
	}

	public void setOrigins(Set<RevocationOrigin> origins) {
		this.origins = origins;
	}

	/**
	 * Returns the online resource availability status
	 * 
	 * @return true if the online resource was available
	 */
	public boolean isAvailable() {
		return available;
	}

	public void setAvailable(boolean available) {
		this.available = available;
	}

	/**
	 * Returns the revocation status
	 * 
	 * @return true if valid, false if revoked/onhold, null if not available
	 */
	public Boolean getStatus() {
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
	 * Returns compiled revocation token key
	 * @return {@link String} key
	 */
	public String getRevocationTokenKey() {
		return revocationTokenKey;
	}
	
	/**
	 * Sets the value for revocationTokenKey
	 * @param key {@link String}
	 */
	public void setRevocationTokenKey(String key) {
		this.revocationTokenKey = key;
	}
	
	/**
	 * Initialize inner attributes
	 */
	public abstract void initInfo();

	/**
	 * Indicates if the token signature is intact and the signing certificate matches with the signature and if the
	 * extended key usage is present.
	 *
	 * @return {@code true} if the conditions are meet
	 */
	public abstract boolean isValid();

	@Override
	public String getDSSIdAsString() {
		return "R-" + super.getDSSIdAsString();
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
		RevocationToken other = (RevocationToken) obj;
		if (!getDSSId().equals(other.getDSSId())) {
			return false;
		}
		if (relatedCertificate == null) {
			if (other.relatedCertificate != null) {
				return false;
			}
		} else if (!relatedCertificate.equals(other.relatedCertificate)) {
			return false;
		}
		return true;
	}

}
