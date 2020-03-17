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
package eu.europa.esig.dss.validation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

/**
 * Check the status of the certificate using an OCSPSource
 *
 */
public class OCSPCertificateVerifier implements CertificateStatusVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPCertificateVerifier.class);

	private final RevocationSource<OCSPToken> ocspSource;


	/**
	 * Create a CertificateVerifier that will use the OCSP Source for checking revocation data. The default constructor
	 * for OCSPCertificateVerifier.
	 *
	 * @param ocspSource
	 */
	public OCSPCertificateVerifier(final RevocationSource<OCSPToken> ocspSource) {
		this.ocspSource = ocspSource;
	}

	@Override
	public RevocationToken check(final CertificateToken toCheckToken, final CertificateToken issuerToken) {
		if (ocspSource == null) {
			LOG.debug("OCSPSource null");
			return null;
		}

		try {
			final OCSPToken ocspToken = ocspSource.getRevocationToken(toCheckToken, issuerToken);
			if (ocspToken == null) {
				LOG.debug("{} : No matching OCSP response found for {}", ocspSource.getClass().getSimpleName(), toCheckToken.getDSSIdAsString());
			} else {
				LOG.trace("An OCSP Response {} is obtained.", ocspToken.getDSSIdAsString());
				LOG.trace("OCSP Response {} status is : {}", ocspToken.getDSSIdAsString(), ocspToken.getStatus());
			}
			return ocspToken;
		} catch (DSSException e) {
			LOG.error("OCSP DSS Exception: " + e.getMessage(), e);
			return null;
		}
	}
	
}
