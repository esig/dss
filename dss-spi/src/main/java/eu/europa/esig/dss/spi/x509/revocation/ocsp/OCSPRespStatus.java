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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * This enum encapsulates constants defined by BouncyCastle and offers a method to parse an int without exception
 *
 */
public enum OCSPRespStatus {

	/** Response has valid confirmations */
	SUCCESSFUL(OCSPResp.SUCCESSFUL),

	/** Illegal confirmation request */
	MALFORMED_REQUEST(OCSPResp.MALFORMED_REQUEST),

	/** Internal error in issuer */
	INTERNAL_ERROR(OCSPResp.INTERNAL_ERROR),

	/** Try again later */
	TRY_LATER(OCSPResp.TRY_LATER),

	/** (4) is not used */
	UNKNOWN_STATUS(4),

	/** Must sign the request */
	SIG_REQUIRED(OCSPResp.SIG_REQUIRED),

	/** Request unauthorized */
	UNAUTHORIZED(OCSPResp.UNAUTHORIZED);

	/** The status code value */
	private final int statusCode;

	/**
	 * Default constructor
	 *
	 * @param statusCode
	 */
	OCSPRespStatus(int statusCode) {
		this.statusCode = statusCode;
	}

	/**
	 * Returns a corresponding {@code OCSPRespStatus} for the int value code
	 *
	 * @param value int code
	 * @return {@link OCSPRespStatus}
	 */
	public static OCSPRespStatus fromInt(int value) {
		for (OCSPRespStatus status : OCSPRespStatus.values()) {
			if (status.statusCode == value) {
				return status;
			}
		}
		return OCSPRespStatus.UNKNOWN_STATUS;
	}

	/**
	 * Returns the status code
	 *
	 * @return status code
	 */
	public int getStatusCode() {
		return statusCode;
	}

}
