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

import java.util.Date;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;

@SuppressWarnings("serial")
public abstract class RevocationToken extends Token {

	private String relatedCertificateID;

	/**
	 * Origin of the revocation data (signature or external)
	 */
	protected RevocationOrigin origin = RevocationOrigin.EXTERNAL;

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
	 * Represents the certHash extension from an OCSP Response (optional)
	 */
	protected Digest certHash;

	/**
	 * The reason of the revocation.
	 */
	protected CRLReasonEnum reason;

	public String getRelatedCertificateID() {
		return relatedCertificateID;
	}

	public void setRelatedCertificateID(String relatedCertificateID) {
		this.relatedCertificateID = relatedCertificateID;
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
	public RevocationOrigin getOrigin() {
		return origin;
	}

	public void setOrigin(RevocationOrigin origin) {
		this.origin = origin;
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
	 * Returns the certHash extension (from an OCSP Response)
	 * 
	 * @return the certHash contains or null
	 */
	public Digest getCertHash() {
		return certHash;
	}

	/**
	 * Returns the revocation reason (if the token has been revoked)
	 * 
	 * @return the revocation reason or null
	 */
	public CRLReasonEnum getReason() {
		return reason;
	}

	/**
	 * Indicates if the token signature is intact and the signing certificate matches with the signature and if the
	 * extended key usage is present.
	 *
	 * @return {@code true} if the conditions are meet
	 */
	public abstract boolean isValid();

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((productionDate == null) ? 0 : productionDate.hashCode());
		result = prime * result + ((relatedCertificateID == null) ? 0 : relatedCertificateID.hashCode());
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
		if (productionDate == null) {
			if (other.productionDate != null) {
				return false;
			}
		} else if (!productionDate.equals(other.productionDate)) {
			return false;
		}
		if (relatedCertificateID == null) {
			if (other.relatedCertificateID != null) {
				return false;
			}
		} else if (!relatedCertificateID.equals(other.relatedCertificateID)) {
			return false;
		}
		return true;
	}

}