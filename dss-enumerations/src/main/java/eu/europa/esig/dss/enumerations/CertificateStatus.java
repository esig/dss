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
package eu.europa.esig.dss.enumerations;

/**
 * Defines the certificate revocation status
 */
public enum CertificateStatus {

	/**
	 * The certificate is not revoked
	 */
	GOOD,

	/**
	 * The certificate is revoked
	 */
	REVOKED,

	/**
	 * The certificate status is not known
	 */
	UNKNOWN;

	/**
	 * Checks if the certificate status is valid
	 *
	 * @return TRUE if the certificate status is valid, FALSE otherwise
	 */
	public boolean isGood() {
		return GOOD == this;
	}

	/**
	 * Checks if the certificate is revoked
	 *
	 * @return TRUE if the certificate is revoked, FALSE otherwise
	 */
	public boolean isRevoked() {
		return REVOKED == this;
	}

	/**
	 * Checks if the certificate status is known
	 *
	 * @return TRUE if the certificate status is known, FALSE otherwise
	 */
	public boolean isKnown() {
		return UNKNOWN != this;
	}

}
