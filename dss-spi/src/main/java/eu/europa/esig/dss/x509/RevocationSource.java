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

import java.io.Serializable;

/**
 * This interface allows to retrieve revocation data for a given certificate.
 * Several implementations are available based on CRL and OCSP.
 */
public interface RevocationSource<T extends RevocationToken> extends Serializable {

	/**
	 * This method retrieves a {@code RevocationToken} for the certificateToken
	 * 
	 * @param certificateToken
	 *                               The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerCertificateToken
	 *                               The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @return an instance of {@code RevocationToken}
	 */
	T getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken);

}
