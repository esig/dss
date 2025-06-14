/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import java.util.Objects;

/**
 * This class provides the different sources used to verify the status of a certificate using the trust model. There are
 * four different types of sources to be defined:<br>
 * - Trusted certificates source;<br>
 * - Adjunct certificates source (not trusted);<br>
 * - OCSP source;<br>
 * - CRL source;<br>
 * - AIA source to give access to the certificates through AIA.
 *
 */
public class CommonCertificateVerifier implements CertificateVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(CommonCertificateVerifier.class);
	
	/**
	 * This field contains the reference to multiple trusted certificate sources. These sources are fixed, it means that the same
	 * sources are used for different validations.
	 */
	private ListCertificateSource trustedCertSources = new ListCertificateSource();

	/**
	 * This field contains the reference to arbitrary certificate source, can contain a trust store, 
	 * or any intermediate certificates.
	 */
	private ListCertificateSource adjunctCertSources = new ListCertificateSource();

	/**
	 * This field contains the reference to the {@code OCSPSource}.
	 */
	private RevocationSource<OCSP> ocspSource;

	/**
	 * This field contains the reference to the {@code CRLSource}.
	 */
	private RevocationSource<CRL> crlSource;

	/**
	 * Creates a revocation data loading strategy used to fetch OCSP or CRL for validating certificates.
	 * <p>
	 * Default: {@code OCSPFirstRevocationDataLoadingStrategyFactory} is used to extract OCSP token first and CRL after
	 */
	private RevocationDataLoadingStrategyFactory revocationDataLoadingStrategyFactory = new OCSPFirstRevocationDataLoadingStrategyFactory();

	/**
	 * Verifies the validity of retrieved revocation data (used to evaluate if a new revocation should be requested).
	 */
	private RevocationDataVerifier revocationDataVerifier;

	/**
	 * Defines whether a revocation data failed a verification still shall be returned to the validation process,
	 * when no valid revocation has been obtained.
	 */
	private boolean revocationFallback = false;

	/**
	 * Verifies validity of a timestamp tokens encapsulated within the signature document.
	 */
	private TimestampTokenVerifier timestampTokenVerifier;

	/**
	 * Verifies validity of trust anchors
	 */
	private TrustAnchorVerifier trustAnchorVerifier;

	/**
	 * The AIA source used to download a certificate's issuer by the AIA URI(s)
	 * defining within a certificate.
	 */
	private AIASource aiaSource;

	/**
	 * This variable set the behavior to follow in case of invalid signature
	 * (augmentation process).
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnInvalidSignature = new ExceptionOnStatusAlert();

	/**
	 * This variable set the behavior to follow in case of invalid timestamp
	 * (augmentation process).
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnInvalidTimestamp = new ExceptionOnStatusAlert();

	/**
	 * This variable set the behavior to follow in case of missing revocation data
	 * (augmentation process).
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnMissingRevocationData = new ExceptionOnStatusAlert();

	/**
	 * This variable set the behavior to follow in case of revoked certificate
	 * (augmentation process).
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnRevokedCertificate = new ExceptionOnStatusAlert();

	/**
	 * This variable set the behavior to follow in case of no revocation data issued
	 * after the bestSignatureTime (augmentation process).
	 * <p>
	 * Default : LogOnStatusAlert - log a warning message
	 */
	private StatusAlert alertOnNoRevocationAfterBestSignatureTime = new LogOnStatusAlert(Level.WARN);

	/**
	 * This variable set the behavior to follow in case of missing revocation data
	 * for a POE.
	 * <p>
	 * Default : LogOnStatusAlert - log a warning message
	 */
	private StatusAlert alertOnUncoveredPOE = new LogOnStatusAlert(Level.WARN);

	/**
	 * Defines a behavior on signature creation with an expired signing-certificate
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnExpiredCertificate = new ExceptionOnStatusAlert();

	/**
	 * Defines a behavior on signature creation with a not yet valid certificate
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnNotYetValidCertificate = new ExceptionOnStatusAlert();

	/**
	 * Defines behavior on signature augmentation when a signature with a higher level is present, than the target one
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert augmentationAlertOnHigherSignatureLevel = new ExceptionOnStatusAlert();

	/**
	 * Defines behavior on augmentation for a signature not containing certificates
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert augmentationAlertOnSignatureWithoutCertificates = new ExceptionOnStatusAlert();

	/**
	 * Defines behavior on augmentation for a signature containing only self-signed certificate chains.
	 * <p>
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert augmentationAlertOnSelfSignedCertificateChains = new ExceptionOnStatusAlert();

	/**
	 * This variable sets the behavior to follow for revocation retrieving in case of
	 * untrusted certificate chains.
	 * <p>
	 * Default : false (revocation are not checked in case of certificates issued
	 * from an unsure source)
	 */
	private boolean checkRevocationForUntrustedChains = false;

	/**
	 * The default constructor. The {@code DataLoader} is created to allow the
	 * retrieval of certificates through AIA.
	 */
	public CommonCertificateVerifier() {
		this(false);
	}

	/**
	 * This constructor allows creating of {@code CommonCertificateVerifier} without {@code DataLoader}.
	 * It means that only a -B profile signature can be created.
	 *
	 * @param simpleCreationOnly
	 *            if true the {@code CommonCertificateVerifier} will not contain {@code AIASource}.
	 */
	public CommonCertificateVerifier(final boolean simpleCreationOnly) {
		LOG.info("+ New CommonCertificateVerifier created.");
		if (!simpleCreationOnly) {
			this.aiaSource = new DefaultAIASource();
		}
	}

	@Override
	public RevocationSource<CRL> getCrlSource() {
		return crlSource;
	}

	@Override
	public void setCrlSource(final RevocationSource<CRL> crlSource) {
		this.crlSource = crlSource;
	}

	@Override
	public RevocationSource<OCSP> getOcspSource() {
		return ocspSource;
	}

	@Override
	public void setOcspSource(final RevocationSource<OCSP> ocspSource) {
		this.ocspSource = ocspSource;
	}

	@Override
	public RevocationDataLoadingStrategyFactory getRevocationDataLoadingStrategyFactory() {
		return revocationDataLoadingStrategyFactory;
	}

	@Override
	public void setRevocationDataLoadingStrategyFactory(RevocationDataLoadingStrategyFactory revocationDataLoadingStrategyFactory) {
		Objects.requireNonNull(revocationDataLoadingStrategyFactory, "RevocationDataLoadingStrategyFactory shall be defined!");
		this.revocationDataLoadingStrategyFactory = revocationDataLoadingStrategyFactory;
	}

	@Override
	public RevocationDataVerifier getRevocationDataVerifier() {
		return revocationDataVerifier;
	}

	@Override
	public void setRevocationDataVerifier(RevocationDataVerifier revocationDataVerifier) {
		this.revocationDataVerifier = revocationDataVerifier;
	}

	@Override
	public boolean isRevocationFallback() {
		return revocationFallback;
	}

	@Override
	public void setRevocationFallback(boolean revocationFallback) {
		this.revocationFallback = revocationFallback;
	}

	@Override
	public TimestampTokenVerifier getTimestampTokenVerifier() {
		return timestampTokenVerifier;
	}

	@Override
	public void setTimestampTokenVerifier(TimestampTokenVerifier timestampTokenVerifier) {
		this.timestampTokenVerifier = timestampTokenVerifier;
	}

	@Override
	public TrustAnchorVerifier getTrustAnchorVerifier() {
		return trustAnchorVerifier;
	}

	@Override
	public void setTrustAnchorVerifier(TrustAnchorVerifier trustAnchorVerifier) {
		this.trustAnchorVerifier = trustAnchorVerifier;
	}

	@Override
	public ListCertificateSource getTrustedCertSources() {
		return trustedCertSources;
	}

	@Override
	public void setTrustedCertSources(final CertificateSource... certSources) {
		this.trustedCertSources = new ListCertificateSource();
		addTrustedCertSources(certSources);
	}
	
	@Override
	public void addTrustedCertSources(final CertificateSource... certSources) {
		for (CertificateSource certificateSource : certSources) {
			if (certificateSource.getCertificateSourceType().isTrusted()) {
				this.trustedCertSources.add(certificateSource);
			} else {
	            throw new UnsupportedOperationException(String.format("The certificateSource with type [%s] is not allowed in the trustedCertSources. Please, "
	                    + "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", certificateSource.getCertificateSourceType()));
			}
		}
	}
	
	@Override
	public void setTrustedCertSources(ListCertificateSource trustedListCertificateSource) {
		if (trustedListCertificateSource == null) {
			this.trustedCertSources = new ListCertificateSource();
		} else if (trustedListCertificateSource.areAllCertSourcesTrusted()) {
			this.trustedCertSources = trustedListCertificateSource;
		} else {
            throw new UnsupportedOperationException("The trusted ListCertificateSource must contain only trusted sources "
                    + "with a type TRUSTED_STORE or TRUSTED_LIST.");
		}
	}

	@Override
	public ListCertificateSource getAdjunctCertSources() {
		return adjunctCertSources;
	}

	@Override
	public void setAdjunctCertSources(final CertificateSource... certSources) {
		this.adjunctCertSources = new ListCertificateSource();
		addAdjunctCertSources(certSources);
	}

	@Override
	public void addAdjunctCertSources(final CertificateSource... certSources) {
		for (CertificateSource certificateSource : certSources) {
			assertNotTrusted(certificateSource);
			this.adjunctCertSources.add(certificateSource);
		}
	}
	
	@Override
	public void setAdjunctCertSources(ListCertificateSource adjunctListCertificateSource) {
		if (adjunctListCertificateSource == null) {
			adjunctListCertificateSource = new ListCertificateSource();
		}
		for (CertificateSource certificateSource : adjunctListCertificateSource.getSources()) {
			assertNotTrusted(certificateSource);
		}
		this.adjunctCertSources = adjunctListCertificateSource;
	}
	
	private void assertNotTrusted(final CertificateSource adjunctCertificateSource) {
		if (adjunctCertificateSource.getCertificateSourceType().isTrusted()) {
			LOG.warn("Adjunct certificate sources shouldn't be trusted. An adjunct certificate source contains missing intermediate certificates");
		}
	}

	@Override
	public AIASource getAIASource() {
		return aiaSource;
	}

	@Override
	public void setAIASource(final AIASource aiaSource) {
		this.aiaSource = aiaSource;
	}

	@Override
	public StatusAlert getAlertOnInvalidSignature() {
		return alertOnInvalidSignature;
	}

	@Override
	public void setAlertOnInvalidSignature(StatusAlert alertOnInvalidSignature) {
		this.alertOnInvalidSignature = alertOnInvalidSignature;
	}

	@Override
	public StatusAlert getAlertOnInvalidTimestamp() {
		return alertOnInvalidTimestamp;
	}

	@Override
	public void setAlertOnInvalidTimestamp(StatusAlert alertOnInvalidTimestamp) {
		this.alertOnInvalidTimestamp = alertOnInvalidTimestamp;
	}

	@Override
	public StatusAlert getAlertOnMissingRevocationData() {
		return alertOnMissingRevocationData;
	}

	@Override
	public void setAlertOnMissingRevocationData(StatusAlert alertOnMissingRevocationData) {
		this.alertOnMissingRevocationData = alertOnMissingRevocationData;
	}

	@Override
	public StatusAlert getAlertOnUncoveredPOE() {
		return alertOnUncoveredPOE;
	}

	@Override
	public void setAlertOnUncoveredPOE(StatusAlert alertOnUncoveredPOE) {
		this.alertOnUncoveredPOE = alertOnUncoveredPOE;
	}

	@Override
	public StatusAlert getAlertOnRevokedCertificate() {
		return alertOnRevokedCertificate;
	}

	@Override
	public void setAlertOnRevokedCertificate(StatusAlert alertOnRevokedCertificate) {
		this.alertOnRevokedCertificate = alertOnRevokedCertificate;
	}

	@Override
	public StatusAlert getAlertOnNoRevocationAfterBestSignatureTime() {
		return alertOnNoRevocationAfterBestSignatureTime;
	}

	@Override
	public void setAlertOnNoRevocationAfterBestSignatureTime(StatusAlert alertOnNoRevocationAfterBestSignatureTime) {
		this.alertOnNoRevocationAfterBestSignatureTime = alertOnNoRevocationAfterBestSignatureTime;
	}

	@Override
	public StatusAlert getAlertOnExpiredCertificate() {
		return alertOnExpiredCertificate;
	}

	@Override
	public void setAlertOnExpiredCertificate(StatusAlert alertOnExpiredCertificate) {
		this.alertOnExpiredCertificate = alertOnExpiredCertificate;
	}

	@Override
	public StatusAlert getAlertOnNotYetValidCertificate() {
		return alertOnNotYetValidCertificate;
	}

	@Override
	public void setAlertOnNotYetValidCertificate(StatusAlert alertOnNotYetValidCertificate) {
		this.alertOnNotYetValidCertificate = alertOnNotYetValidCertificate;
	}

	@Override
	public StatusAlert getAugmentationAlertOnHigherSignatureLevel() {
		return augmentationAlertOnHigherSignatureLevel;
	}

	@Override
	public void setAugmentationAlertOnHigherSignatureLevel(StatusAlert augmentationAlertOnHigherSignatureLevel) {
		this.augmentationAlertOnHigherSignatureLevel = augmentationAlertOnHigherSignatureLevel;
	}

	@Override
	public StatusAlert getAugmentationAlertOnSignatureWithoutCertificates() {
		return augmentationAlertOnSignatureWithoutCertificates;
	}

	@Override
	public void setAugmentationAlertOnSignatureWithoutCertificates(StatusAlert augmentationAlertOnSignatureWithoutCertificates) {
		this.augmentationAlertOnSignatureWithoutCertificates = augmentationAlertOnSignatureWithoutCertificates;
	}

	@Override
	public StatusAlert getAugmentationAlertOnSelfSignedCertificateChains() {
		return augmentationAlertOnSelfSignedCertificateChains;
	}

	@Override
	public void setAugmentationAlertOnSelfSignedCertificateChains(StatusAlert augmentationAlertOnSelfSignedCertificateChains) {
		this.augmentationAlertOnSelfSignedCertificateChains = augmentationAlertOnSelfSignedCertificateChains;
	}

	@Override
	public boolean isCheckRevocationForUntrustedChains() {
		return checkRevocationForUntrustedChains;
	}

	@Override
	public void setCheckRevocationForUntrustedChains(boolean checkRevocationForUntrustedChains) {
		this.checkRevocationForUntrustedChains = checkRevocationForUntrustedChains;
	}

}
