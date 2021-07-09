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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.RevocationReason;

import java.util.Date;

/**
 * Complete revocation wrapper, containing detailed certificate revocation and common information
 */
public class CertificateRevocationWrapper extends RevocationWrapper {
	
	/** Wrapped {@code XmlCertificateRevocation} */
	private final XmlCertificateRevocation certificateRevocation;
	
	/**
	 * Default constructor
	 *
	 * @param certificateRevocation {@link XmlCertificateRevocation}
	 */
	public CertificateRevocationWrapper(XmlCertificateRevocation certificateRevocation) {
		super(certificateRevocation.getRevocation());
		this.certificateRevocation = certificateRevocation;
	}

	/**
	 * Returns the revocation status of the concerned certificate
	 *
	 * @return {@link CertificateStatus}
	 */
	public CertificateStatus getStatus() {
		return certificateRevocation.getStatus();
	}

	/**
	 * Returns the revocation reason for the concerned certificate
	 *
	 * @return {@link RevocationReason}
	 */
	public RevocationReason getReason() {
		return certificateRevocation.getReason();
	}

	/**
	 * Returns the revocation time for the concerned certificate
	 *
	 * @return {@link Date}
	 */
	public Date getRevocationDate() {
		return certificateRevocation.getRevocationDate();
	}

	/**
	 * Gets if the concerned certificate has been revoked
	 *
	 * @return TRUE if the certificate has been revoked, FALSE otherwise
	 */
	public boolean isRevoked() {
		return getStatus().isRevoked();
	}

	/**
	 * Gets if the revocation status is known
	 *
	 * @return TRUE if the revocation status is known, FALSE otherwise
	 */
	public boolean isKnown() {
		return getStatus().isKnown();
	}
	
}
