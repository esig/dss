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
import eu.europa.esig.dss.spi.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSP;

/**
 * Fetchs revocation data for a certificate by querying an OCSP server first and
 * then a CRL server if no OCSP response could be retrieved.
 *
 */
public class OCSPAndCRLRevocationSource implements RevocationSource<Revocation> {

	private static final long serialVersionUID = 3205352844337899410L;

	private static final Logger LOG = LoggerFactory.getLogger(OCSPAndCRLRevocationSource.class);

	private final RevocationSource<OCSP> ocspSource;

	private final RevocationSource<CRL> crlSource;

	/**
	 * Build a OCSPAndCRLCertificateVerifier that will use the provided CRLSource
	 * and OCSPSource
	 *
	 * @param crlSource
	 *                           the used CRL Source (online or offline)
	 * @param ocspSource
	 *                           the used OCSP Source (online or offline)
	 */
	public OCSPAndCRLRevocationSource(final RevocationSource<CRL> crlSource, final RevocationSource<OCSP> ocspSource) {
		this.crlSource = crlSource;
		this.ocspSource = ocspSource;
	}

	/**
	 * This method tries firstly to collect from the OCSP Source and than from the
	 * CRL Source. The first result is returned.
	 * 
	 * 
	 */
	@Override
	public RevocationToken<Revocation> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {
		if (LOG.isTraceEnabled()) {
			LOG.trace("Check revocation for certificate : {}", certificateToken.getDSSIdAsString());
		}
		RevocationToken result = checkOCSP(certificateToken, issuerToken);
		if (result != null) {
			return result;
		}
		result = checkCRL(certificateToken, issuerToken);
		if (result != null) {
			return result;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("There is no response for {} neither from OCSP nor from CRL!", certificateToken.getDSSIdAsString());
		}
		return null;
	}

	public RevocationToken<OCSP> checkOCSP(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		if (ocspSource == null) {
			LOG.debug("OCSPSource null");
			return null;
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("OCSP request for: {} using: {}", certificateToken.getDSSIdAsString(), ocspSource.getClass().getSimpleName());
		}
		try {
			final RevocationToken<OCSP> revocationToken = ocspSource.getRevocationToken(certificateToken, issuerToken);
			if (revocationToken != null && revocationToken.getStatus() != null) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("OCSP response for {} retrieved: {}", certificateToken.getDSSIdAsString(), revocationToken.getAbbreviation());
					LOG.debug("OCSP Response {} status is : {}", revocationToken.getDSSIdAsString(), revocationToken.getStatus());
				}
				return revocationToken;
			}
		} catch (DSSException e) {
			LOG.error("OCSP DSS Exception: {}", e.getMessage(), e);
			return null;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("The retrieved OCSP revocation response for token {} is null!", certificateToken.getDSSIdAsString());
		}
		return null;
	}

	public RevocationToken<CRL> checkCRL(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		if (crlSource == null) {
			LOG.debug("CRLSource is null");
			return null;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("CRL request for: {} using: {}", certificateToken.getDSSIdAsString(), crlSource.getClass().getSimpleName());
		}
		try {
			final RevocationToken<CRL> revocationToken = crlSource.getRevocationToken(certificateToken, issuerToken);
			if (revocationToken != null && revocationToken.getStatus() != null) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("CRL for {} retrieved: {}", certificateToken.getDSSIdAsString(), revocationToken.getAbbreviation());
				}
				return revocationToken;
			}
		} catch (DSSException e) {
			LOG.error("CRL DSS Exception: {}", e.getMessage(), e);
			return null;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("The retrieved CRL revocation response for token {} is null!", certificateToken.getDSSIdAsString());
		}
		return null;
	}

}
