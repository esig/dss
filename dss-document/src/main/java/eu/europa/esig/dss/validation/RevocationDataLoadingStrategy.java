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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class allows retrieving of Revocation data from CRL or OCSP sources, based on the defined strategy
 *
 * NOTE: The implemented object does not require setting of OCSP/CRL/RevocationDataVerifier sources
 *       on instantiation from the user.
 *       All the values are automatically configured and set in {@code eu.europa.esig.dss.validation.SignatureValidationContext}
 *       based on the parameters defined in the provided {@code eu.europa.esig.dss.validation.CertificateVerifier}
 *
 */
public abstract class RevocationDataLoadingStrategy {

	private static final Logger LOG = LoggerFactory.getLogger(RevocationDataLoadingStrategy.class);

	/**
	 * The CRL revocation source
	 */
	protected RevocationSource<CRL> crlSource;

	/**
	 * The OCSP revocation source
	 */
	protected RevocationSource<OCSP> ocspSource;

	/**
	 * Used to verify the validity of obtained revocation data
	 */
	protected RevocationDataVerifier revocationDataVerifier = new RevocationDataVerifier();

	/**
	 * When enabled, returns first obtained revocation token, if both OCSP and CRL requests failed
	 */
	protected boolean fallbackEnabled = false;

	/**
	 * Sets the CRLSource
	 *
	 * @param crlSource {@link RevocationSource}
	 */
	void setCrlSource(RevocationSource<CRL> crlSource) {
		this.crlSource = crlSource;
	}

	/**
	 * Sets the OCSPSource
	 *
	 * @param ocspSource {@link RevocationSource}
	 */
	void setOcspSource(RevocationSource<OCSP> ocspSource) {
		this.ocspSource = ocspSource;
	}

	/**
	 * Sets {@code RevocationDataVerifier}
	 *
	 * @param revocationDataVerifier {@link RevocationDataVerifier}
	 */
	void setRevocationDataVerifier(RevocationDataVerifier revocationDataVerifier) {
		this.revocationDataVerifier = revocationDataVerifier;
	}

	/**
	 * Sets whether the fallback shall be enabled.
	 * When set to TRUE, returns the first obtained token, even when it is not acceptable by the verifier.
	 *
	 * Default : FALSE - no fallback. If tokens fail the validation, NULL is returned.
	 *
	 * @param fallbackEnabled TRUE if the fallback shall be enabled, FALSE otherwise
	 */
	void setFallbackEnabled(boolean fallbackEnabled) {
		this.fallbackEnabled = fallbackEnabled;
	}

	/**
	 * This method retrieves a {@code RevocationToken} for the given certificateToken
	 *
	 * @param certificateToken
	 *                               The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerCertificateToken
	 *                               The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @return an instance of {@code RevocationToken}
	 */
	@SuppressWarnings("rawtypes")
	public abstract RevocationToken getRevocationToken(CertificateToken certificateToken,
														  CertificateToken issuerCertificateToken);

	/**
	 * Retrieves and verifies the obtained CRL token
	 *
	 * NOTE: returns only if a valid entry has been obtained!
	 *
	 * @param certificateToken {@link CertificateToken} to get CRL for
	 * @param issuerToken {@link CertificateToken} issuer of {@code certificateToken}
	 * @return {@link RevocationToken}
	 */
	protected RevocationToken<CRL> checkCRL(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		if (crlSource == null) {
			LOG.debug("CRLSource is null");
			return null;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("CRL request for: {} using: {}", certificateToken.getDSSIdAsString(), crlSource.getClass().getSimpleName());
		}
		try {
			final RevocationToken<CRL> revocationToken = crlSource.getRevocationToken(certificateToken, issuerToken);
			if (revocationToken != null) {
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
			LOG.debug("A CRL for token {} is not obtained! Return null value.", certificateToken.getDSSIdAsString());
		}
		return null;
	}

	/**
	 * Retrieves and verifies the obtained OCSP token
	 *
	 * NOTE: returns only if a valid entry has been obtained!
	 *
	 * @param certificateToken {@link CertificateToken} to get OCSP for
	 * @param issuerToken {@link CertificateToken} issuer of {@code certificateToken}
	 * @return {@link RevocationToken}
	 */
	protected RevocationToken<OCSP> checkOCSP(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		if (ocspSource == null) {
			LOG.debug("OCSPSource null");
			return null;
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("OCSP request for: {} using: {}", certificateToken.getDSSIdAsString(), ocspSource.getClass().getSimpleName());
		}
		try {
			final RevocationToken<OCSP> revocationToken = ocspSource.getRevocationToken(certificateToken, issuerToken);
			if (revocationToken != null) {
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
			LOG.debug("An OCSP response for token {} is not obtained! Return null value.", certificateToken.getDSSIdAsString());
		}
		return null;
	}

	/**
	 * This method verifies whether the obtained revocation token is acceptable
	 *
	 * @param revocationToken {@link RevocationToken} to be checked
	 * @return TRUE if the token is acceptable and can be returned, FALSE otherwise
	 */
	protected boolean isAcceptableToken(RevocationToken<?> revocationToken) {
		if (revocationDataVerifier == null) {
			LOG.warn("RevocationDataVerifier is null! Validation of retrieved revocation data is skipped.");
			return true;
		}
		return revocationDataVerifier.isAcceptable(revocationToken);
	}

}
