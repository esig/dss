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

import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.CRLToken;

/**
 * Verifier based on CRL
 *
 */
public class CRLCertificateVerifier implements CertificateStatusVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(CRLCertificateVerifier.class);

	private final CRLSource crlSource;

	private final CertificatePool validationCertPool;

	/**
	 * Main constructor.
	 *
	 * @param crlSource
	 *                           the CRL repository used by this CRL trust linker.
	 * @param validationCertPool
	 */
	public CRLCertificateVerifier(final CRLSource crlSource, final CertificatePool validationCertPool) {
		this.crlSource = crlSource;
		this.validationCertPool = validationCertPool;
	}

	@Override
	public RevocationToken check(final CertificateToken certificateToken) {
		try {
			if (crlSource == null) {
				LOG.debug("CRLSource is null");
				return null;
			}

			CertificateToken issuerToken = validationCertPool.getIssuer(certificateToken);
			if (issuerToken == null) {
				LOG.debug("Issuer is null");
				return null;
			}

			final CRLToken crlToken = crlSource.findCrl(certificateToken, issuerToken);
			if (crlToken == null) {
				LOG.debug("No CRL found for: " + certificateToken.getDSSIdAsString());
				return null;
			}
			crlToken.setRelatedCertificateID(certificateToken.getDSSIdAsString());
			if (!crlToken.isValid()) {
				LOG.warn("The CRL is not valid !");
				return null;
			}
			return crlToken;
		} catch (final Exception e) {
			LOG.error("Exception when accessing CRL for " + certificateToken.getDSSIdAsString(), e);
			return null;
		}
	}
}
