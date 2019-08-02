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
import eu.europa.esig.dss.x509.revocation.RevocationSource;
import eu.europa.esig.dss.x509.revocation.RevocationToken;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;

/**
 * Fetchs revocation data from a certificate by querying an OCSP server first and then a CRL server if no OCSP response
 * could be retrieved.
 *
 */
public class OCSPAndCRLCertificateVerifier implements CertificateStatusVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPAndCRLCertificateVerifier.class);

	private final RevocationSource<OCSPToken> ocspSource;

	private final RevocationSource<CRLToken> crlSource;

	private final CertificatePool validationCertPool;

	/**
	 * Build a OCSPAndCRLCertificateVerifier that will use the provided CRLSource
	 * and OCSPSource
	 *
	 * @param crlSource
	 *                           the used CRL Source (online or offline)
	 * @param ocspSource
	 *                           the used OCSP Source (online or offline)
	 * @param validationCertPool
	 *                           the used Certificate pool
	 */
	public OCSPAndCRLCertificateVerifier(final RevocationSource<CRLToken> crlSource, final RevocationSource<OCSPToken> ocspSource,
			final CertificatePool validationCertPool) {
		this.crlSource = crlSource;
		this.ocspSource = ocspSource;
		this.validationCertPool = validationCertPool;
	}

	@Override
	public RevocationToken check(final CertificateToken certificateToken) {
		if (LOG.isTraceEnabled()) {
			LOG.trace("Check revocation for certificate : {}", certificateToken.getDSSIdAsString());
		}
		RevocationToken result = checkOCSP(certificateToken);
		if (result != null) {
			return result;
		}
		result = checkCRL(certificateToken);
		if (result != null) {
			return result;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("There is no response for {} neither from OCSP nor from CRL!", certificateToken.getDSSIdAsString());
		}
		return null;
	}

	public RevocationToken checkOCSP(final CertificateToken certificateToken) {
		if (ocspSource != null) {
			final OCSPCertificateVerifier ocspVerifier = new OCSPCertificateVerifier(ocspSource, validationCertPool);
			if (LOG.isDebugEnabled()) {
				LOG.debug("OCSP request for: {} using: {}", certificateToken.getDSSIdAsString(),
						ocspSource.getClass().getSimpleName());
			}
			final RevocationToken revocation = ocspVerifier.check(certificateToken);
			if (revocation != null && revocation.getStatus() != null) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("OCSP response for {} retrieved: {}", certificateToken.getDSSIdAsString(), revocation.getAbbreviation());
				}
				return revocation;
			}
		}
		return null;
	}

	public RevocationToken checkCRL(final CertificateToken certificateToken) {
		if (crlSource != null) {
			final CRLCertificateVerifier crlVerifier = new CRLCertificateVerifier(crlSource, validationCertPool);
			if (LOG.isDebugEnabled()) {
				LOG.debug("CRL request for: {} using: {}", certificateToken.getDSSIdAsString(), crlSource.getClass().getSimpleName());
			}
			final RevocationToken revocationToken = crlVerifier.check(certificateToken);
			if (revocationToken != null && revocationToken.getStatus() != null) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("CRL for {} retrieved: {}", certificateToken.getDSSIdAsString(), revocationToken.getAbbreviation());
				}
				return revocationToken;
			}
		}
		return null;
	}

}
