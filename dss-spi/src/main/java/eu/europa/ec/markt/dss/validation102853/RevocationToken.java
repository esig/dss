/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.validation102853;

import java.util.Date;

public abstract class RevocationToken extends Token {

	/**
	 * Contains the revocation status of the token. True if is not revoked, false if is revoked or null if unknown.
	 */
	protected Boolean status;

	/**
	 * Represents the this update date of the CRL or the production date of the OCSP response.
	 */
	protected Date issuingTime;

	/**
	 * Represents the next update date of the CRL or null for OCSP response.
	 */
	protected Date nextUpdate;

	/**
	 * Represents the revocation date from an X509CRLEntry or from an BasicOCSPResp<br>
	 * --> getResponses() --> ((RevokedStatus) singleResp.getCertStatus()).getRevocationTime()
	 */
	protected Date revocationDate;

	/**
	 * The reason of the revocation.
	 */
	protected String reason;

	/**
	 * @return
	 */
	public Boolean getStatus() {
		return status;
	}

	/**
	 * @return
	 */
	public Date getIssuingTime() {
		return issuingTime;
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

	/**
	 * @return
	 */
	public String getReason() {
		return reason;
	}

	/**
	 * Indicates if the token signature is intact and the signing certificate matches with the signature and if the extended key usage is present.
	 *
	 * @return {@code true} if the conditions are meet
	 */
	public abstract boolean isValid();


	public abstract String getSourceURL();

}