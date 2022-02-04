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
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class allows retrieving of Revocation data from CRL or OCSP sources, based on the defined strategy
 *
 * NOTE: The implemented object does not require setting of OCSP/CRL/TrustedCertificate sources
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
	 * The trusted certificate source is used to accept trusted OCSPToken's certificate issuers
	 */
	protected ListCertificateSource trustedListCertificateSource;

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
	 * Sets a trusted certificate source in order to accept trusted OCSPToken's certificate issuers
	 * 
	 * @param trustedListCertificateSource {@link ListCertificateSource}
	 */
	void setTrustedCertificateSource(ListCertificateSource trustedListCertificateSource) {
		this.trustedListCertificateSource = trustedListCertificateSource;
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
	protected abstract RevocationToken getRevocationToken(CertificateToken certificateToken,
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
			if (revocationToken != null && containsCertificateStatus(revocationToken)) {
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
			if (revocationToken != null && containsCertificateStatus(revocationToken) && isAcceptable(revocationToken)
					&& isIssuerValidAtRevocationProductionTime(revocationToken)) {
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

	private boolean containsCertificateStatus(RevocationToken<?> revocationToken) {
		if (revocationToken.getStatus() == null) {
			LOG.warn("The obtained revocation token does not contain the certificate status. "
					+ "The token is skipped.");
			return false;
		}
		return true;
	}

	private boolean isAcceptable(RevocationToken<OCSP> ocspToken) {
		CertificateToken issuerCertificateToken = ocspToken.getIssuerCertificateToken();
		if (issuerCertificateToken == null) {
			LOG.warn("The issuer certificate is not found for the obtained OCSPToken. "
					+ "The token is skipped.");
			return false;

		} else if (doesRequireRevocation(issuerCertificateToken) && !hasRevocationAccessPoints(issuerCertificateToken)) {
			LOG.warn("The issuer certificate of the obtained OCSPToken requires a revocation data, "
					+ "which is not acceptable due its configuration (no revocation access location points). The token is skipped.");
			return false;

		}
		return true;
	}

	private boolean doesRequireRevocation(final CertificateToken certificateToken) {
		if (certificateToken.isSelfSigned()) {
			return false;
		}
		if (isTrusted(certificateToken)) {
			return false;
		}
		if (DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certificateToken)) {
			return false;
		}
		return true;
	}

	private boolean isTrusted(CertificateToken certificateToken) {
		return trustedListCertificateSource != null && trustedListCertificateSource.isTrusted(certificateToken);
	}

	private boolean hasRevocationAccessPoints(final CertificateToken certificateToken) {
		if (Utils.isCollectionNotEmpty(DSSASN1Utils.getOCSPAccessLocations(certificateToken))) {
			return true;
		}
		if (Utils.isCollectionNotEmpty(DSSASN1Utils.getCrlUrls(certificateToken))) {
			return true;
		}
		return false;
	}

	private boolean isIssuerValidAtRevocationProductionTime(RevocationToken<?> revocationToken) {
		if (!DSSRevocationUtils.checkIssuerValidAtRevocationProductionTime(revocationToken)) {
			LOG.warn("The revocation token has been produced outside the issuer certificate's validity range. "
					+ "The token is skipped.");
			return false;
		}
		return true;
	}

}
