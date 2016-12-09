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

@SuppressWarnings("serial")
public abstract class RevocationToken extends Token {

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
	 * Represents the revocation date from an X509CRLEntry or from an BasicOCSPResp<br>
	 * --> getResponses() --> ((RevokedStatus) singleResp.getCertStatus()).getRevocationTime()
	 */
	protected Date revocationDate;

	protected Date expiredCertsOnCRL;

	protected Date archiveCutOff;

	/**
	 * The reason of the revocation.
	 */
	protected String reason;

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

	public RevocationOrigin getOrigin() {
		return origin;
	}

	public void setOrigin(RevocationOrigin origin) {
		this.origin = origin;
	}

	public boolean isAvailable() {
		return available;
	}

	public void setAvailable(boolean available) {
		this.available = available;
	}

	/**
	 * @return
	 */
	public Boolean getStatus() {
		return status;
	}

	public Date getProductionDate() {
		return productionDate;
	}

	public Date getThisUpdate() {
		return thisUpdate;
	}

	/**
	 * @return
	 */
	public Date getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * @return
	 */
	public Date getRevocationDate() {
		return revocationDate;
	}

	public Date getExpiredCertsOnCRL() {
		return expiredCertsOnCRL;
	}

	public Date getArchiveCutOff() {
		return archiveCutOff;
	}

	/**
	 * @return
	 */
	public String getReason() {
		return reason;
	}

	/**
	 * Indicates if the token signature is intact and the signing certificate matches with the signature and if the
	 * extended key usage is present.
	 *
	 * @return {@code true} if the conditions are meet
	 */
	public abstract boolean isValid();

}