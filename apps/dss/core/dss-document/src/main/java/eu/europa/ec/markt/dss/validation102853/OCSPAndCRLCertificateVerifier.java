/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.validation102853.crl.CRLSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPSource;

/**
 * Fetchs revocation data from a certificate by querying an OCSP server first and then a CRL server if no OCSP response
 * could be retrieved.
 *
 * @version $Revision: 1820 $ - $Date: 2013-03-28 15:55:47 +0100 (Thu, 28 Mar 2013) $
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
