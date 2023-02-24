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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;

import java.io.Serializable;
import java.util.List;

/**
 * This interface allows to retrieve all revocation data for a given
 * certificate.
 * Several implementations are available based on CRL and OCSP.
 *
 * @param <R> implementation of {@code Revocation} (CRL or OCSP) for the current revocation source
 */
public interface MultipleRevocationSource<R extends Revocation> extends Serializable {

	/**
	 * This method retrieves a list of {@code RevocationToken} for the
	 * certificateToken
	 * 
	 * @param certificateToken       The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerCertificateToken The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @return a list of {@code RevocationToken}
	 */
	List<RevocationToken<R>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerCertificateToken);

}
