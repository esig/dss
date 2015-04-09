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
package eu.europa.esig.dss.x509.ocsp;

import java.io.Serializable;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;

/**
 * The validation of a certificate may require the use of OCSP information. Theses information can be provided by multiple sources
 * (the signature itself, online OCSP server, ...). This interface provides an abstraction for a source of OCSPResp
 *
 *
 */

public interface OCSPSource extends Serializable {

	/**
	 * Gets an {@code OCSPToken} for the given certificate / issuer's certificate couple. The coherence between the response and the request is checked.
	 *
	 * @param certificateToken The {@code CertificateToken} for which the request is made
	 * @param issuerCertificateToken The {@code CertificateToken} which is the issuer of the certificateToken
	 * @return {@code OCSPToken} containing information about the validity of the cert
	 */
	OCSPToken getOCSPToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken);
}
