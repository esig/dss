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
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * Fetchs revocation data from a certificate by querying an OCSP server first and then a CRL server if no OCSP response
 * could be retrieved.
 *
 *
 */

public class OCSPAndCRLCertificateVerifier implements CertificateStatusVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPAndCRLCertificateVerifier.class);

	private OCSPSource ocspSource;

	private CRLSource crlSource;

	private final CertificatePool validationCertPool;

	/**
	 * Build a OCSPAndCRLCertificateVerifier that will use the provided CRLSource and OCSPSource
	 *
	 * @param crlSource
	 * @param ocspSource
	 * @param validationCertPool
	 */
	public OCSPAndCRLCertificateVerifier(final CRLSource crlSource, final OCSPSource ocspSource, final CertificatePool validationCertPool) {

		this.crlSource = crlSource;
		this.ocspSource = ocspSource;
		this.validationCertPool = validationCertPool;
	}

	@Override
	public RevocationToken check(final CertificateToken certificateToken) {

		if (LOG.isTraceEnabled()) {
			LOG.trace(certificateToken.toString());
		}
		final boolean debugEnabled = LOG.isDebugEnabled();
		final String dssIdAsString = certificateToken.getDSSIdAsString();
		if (ocspSource != null) {

			final OCSPCertificateVerifier ocspVerifier = new OCSPCertificateVerifier(ocspSource, validationCertPool);
			if (debugEnabled) {
				LOG.debug("OCSP request for: " + dssIdAsString + " using: " + ocspSource.getClass().getSimpleName());
			}
			final RevocationToken revocation = ocspVerifier.check(certificateToken);
			if (revocation != null && revocation.getStatus() != null) {

				if (debugEnabled) {
					LOG.debug("OCSP response for " + dssIdAsString + " retrieved: " + revocation.getAbbreviation());
				}
				return revocation;
			}
		}
		if (crlSource != null) {

			if (debugEnabled) {
				LOG.debug("CRL request for: " + dssIdAsString + " using: " + crlSource.getClass().getSimpleName());
			}
			/**
			 * The validationPool is not needed for the CRLCertificateVerifier because it should be signed by the same certificate as the
			 * certificate to be checked. But: - a CA Designated Responder (Authorized Responder, defined in
			 Section 4.2.2.2) who holds a specially marked certificate issued
			 directly by the CA, indicating that the responder may issue OCSP
			 responses for that CA.

			 */
			final CRLCertificateVerifier crlVerifier = new CRLCertificateVerifier(crlSource);
			final RevocationToken revocationToken = crlVerifier.check(certificateToken);
			if (revocationToken != null && revocationToken.getStatus() != null) {

				if (debugEnabled) {
					LOG.debug("CRL for " + dssIdAsString + " retrieved: " + revocationToken.getAbbreviation());
				}
				return revocationToken;
			}
		}
		if (debugEnabled) {
			LOG.debug("There is no response for " + dssIdAsString + " neither from OCSP nor from CRL!");
		}
		return null;
	}
}
