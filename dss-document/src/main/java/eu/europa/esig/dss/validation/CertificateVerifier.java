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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

/**
 * Provides information on the sources to be used in the validation process in
 * the context of a signature.
 */
public interface CertificateVerifier {

	/**
	 * Returns the CRL source associated with this verifier.
	 *
	 * @return the used CRL source for external access (web, filesystem, cached,...)
	 */
	RevocationSource<CRL> getCrlSource();

	/**
	 * Defines the source of CRL used by this class
	 *
	 * @param crlSource
	 *                  the CRL source to set for external access (web, filesystem,
	 *                  cached,...)
	 */
	void setCrlSource(final RevocationSource<CRL> crlSource);

	/**
	 * Returns the OCSP source associated with this verifier.
	 *
	 * @return the used OCSP source for external access (web, filesystem,
	 *         cached,...)
	 */
	RevocationSource<OCSP> getOcspSource();

	/**
	 * Defines the source of OCSP used by this class
	 *
	 * @param ocspSource
	 *                   the OCSP source to set for external access (web,
	 *                   filesystem, cached,...)
	 */
	void setOcspSource(final RevocationSource<OCSP> ocspSource);

	/**
	 * Returns a revocation data loading strategy associated with this verifier.
	 *
	 * @return the defined strategy to fetch OCSP or CRL for certificate validation
	 */
	RevocationDataLoadingStrategy getRevocationDataLoadingStrategy();

	/**
	 * Defines a strategy used to fetch OCSP or CRL for certificate validation.
	 *
	 * Default: {@code OCSPFirstRevocationDataLoadingStrategy} is used to extract OCSP token first and CRL after
	 *
	 * @param revocationDataLoadingStrategy
	 *                   {@link RevocationDataLoadingStrategy}
	 */
	void setRevocationDataLoadingStrategy(final RevocationDataLoadingStrategy revocationDataLoadingStrategy);

	/**
	 * Returns the trusted certificate sources associated with this verifier. These
	 * sources are used to identify the trusted anchors.
	 *
	 * @return the certificate sources which contain trusted certificates
	 */
	ListCertificateSource getTrustedCertSources();

	/**
	 * Sets multiple trusted certificate sources.
	 *
	 * @param certSources
	 *                   The certificate sources with known trusted certificates
	 */
	void setTrustedCertSources(final CertificateSource... certSources);

	/**
	 * Adds trusted certificate sources to an existing list of trusted certificate sources
	 *
	 * @param certSources
	 *                   The certificate sources with known trusted certificates
	 */
	void addTrustedCertSources(final CertificateSource... certSources);

	/**
	 * Sets a list of trusted certificate sources
	 *
	 * @param trustedListCertificateSource
	 *                   {@link ListCertificateSource} of trusted cert sources
	 */
	void setTrustedCertSources(final ListCertificateSource trustedListCertificateSource);

	/**
	 * Returns the list of adjunct certificate sources assigned to this verifier.
	 *
	 * @return the certificate source which contains additional certificate (missing
	 *         CA,...)
	 */
	ListCertificateSource getAdjunctCertSources();

	/**
	 * Sets multiple adjunct certificate sources.
	 *
	 * @param certSources
	 *                          the certificate sources with additional and/or missing
	 *                          certificates
	 */
	void setAdjunctCertSources(final CertificateSource... certSources);

	/**
	 * Adds adjunct certificate sources to an existing list of adjunct certificate sources
	 *
	 * @param certSources
	 *                   The certificate sources with additional certificates
	 */
	void addAdjunctCertSources(final CertificateSource... certSources);

	/**
	 * Sets a list of adjunct certificate sources
	 *
	 * @param adjunctListCertificateSource
	 *                   {@link ListCertificateSource} of adjunct cert sources
	 */
	void setAdjunctCertSources(final ListCertificateSource adjunctListCertificateSource);

	/**
	 * The data loader used to access AIA certificate source. If this property is
	 * not set the default {@code CommonsHttpDataLoader} is created.
	 *
	 * @param dataLoader
	 *                   the used data loaded to load AIA resources and policy files
	 * @deprecated since v5.9
	 *
	 * Please, use the following code to define the {@code AIASource}:
	 * {@code
	 *       AIASource aiaSource = new DefaultAIASource(dataLoader);
	 * 		 certificateVerifier.setAIASource(aiaSource);
	 * }
	 *
	 * And the code to define a {@code DataLoader} for signature policy loading:
	 * {@code
	 *       SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
	 *       signaturePolicyProvider.setDataLoader(dataLoader);
	 * 		 documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);
	 * }
	 */
	@Deprecated
	void setDataLoader(final DataLoader dataLoader);

	/**
	 * Gets the AIASource used to load a {@code eu.europa.esig.dss.model.x509.CertificateToken}'s issuer
	 * by defined AIA URI(s) within the token
	 *
	 * @return aiaSource {@link AIASource}
	 */
	AIASource getAIASource();

	/**
	 * Sets the AIASource used to load a {@code eu.europa.esig.dss.model.x509.CertificateToken}'s issuer
	 * by defined AIA URI(s) within the token
	 *
	 * @param aiaSource {@link AIASource}
	 */
	void setAIASource(final AIASource aiaSource);

	/**
	 * This method allows to change the Digest Algorithm that will be used for tokens' digest calculation
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use
	 */
	void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm);
	
	/**
	 * This method returns a default Digest Algorithm what will be used for digest calculation
	 *
	 * @return {@link DigestAlgorithm}
	 */
	DigestAlgorithm getDefaultDigestAlgorithm();
	
	/**
	 * This method allows to change the behavior on invalid timestamp (LT/LTA
	 * augmentation).
	 * 
	 * Default : {@link ExceptionOnStatusAlert} - throw an exception.
	 * 
	 * @param alertOnInvalidTimestamp defines a behaviour in case of invalid
	 *                                timestamp
	 */
	void setAlertOnInvalidTimestamp(StatusAlert alertOnInvalidTimestamp);

	/**
	 * This method returns the defined execution behaviour on invalid timestamp.
	 * 
	 * @return {@link StatusAlert} to be processed in case of an invalid timestamp
	 */
	StatusAlert getAlertOnInvalidTimestamp();

	/**
	 * This method allows to change the behavior on missing revocation data (LT/LTA
	 * augmentation).
	 * 
	 * Default : {@link ExceptionOnStatusAlert} - throw an exception.
	 * 
	 * @param alertOnMissingRevocationData defines a behaviour in case of missing
	 *                                     revocation data
	 */
	void setAlertOnMissingRevocationData(StatusAlert alertOnMissingRevocationData);

	/**
	 * This method returns the defined execution behaviour on missing revocation data.
	 * 
	 * @return {@link StatusAlert} to be processed in case of missing revocation
	 *         data
	 */
	StatusAlert getAlertOnMissingRevocationData();

	/**
	 * This method allows to change the behavior on revoked certificates (LT/LTA
	 * augmentation).
	 * 
	 * Default : {@link ExceptionOnStatusAlert} - throw an exception.
	 * 
	 * @param alertOnRevokedCertificate defines a behaviour in case of revoked
	 *                                  certificate
	 */
	void setAlertOnRevokedCertificate(StatusAlert alertOnRevokedCertificate);

	/**
	 * This method returns the defined execution behaviour on revoked certificate.
	 * 
	 * @return {@link StatusAlert} to be processed in case of revoked certificate
	 */
	StatusAlert getAlertOnRevokedCertificate();

	/**
	 * This method allows to change the behavior on revocation data issued after a
	 * control time.
	 * 
	 * Default : {@link LogOnStatusAlert} - log a warning.
	 * 
	 * @param alertOnNoRevocationAfterBestSignatureTime defines a behaviour in case
	 *                                                  of no revocation data issued
	 *                                                  after the bestSignatureTime
	 */
	void setAlertOnNoRevocationAfterBestSignatureTime(StatusAlert alertOnNoRevocationAfterBestSignatureTime);
	
	/**
	 * This method returns the defined execution behaviour if no
	 * revocation data obtained with an issuance time after the bestSignatureTime
	 * 
	 * @return {@link StatusAlert} to be processed in case of no revocation data
	 *         after best signature time
	 */
	StatusAlert getAlertOnNoRevocationAfterBestSignatureTime();
	
	/**
	 * This method allows to change the behavior on uncovered POE (timestamp).
	 * 
	 * Default : {@link LogOnStatusAlert} - log a warning.
	 * 
	 * @param alertOnUncoveredPOE defines a behaviour in case of uncovered POE
	 */
	void setAlertOnUncoveredPOE(StatusAlert alertOnUncoveredPOE);
	
	/**
	 * This method returns the defined execution behaviour on uncovered POE (timestamp).
	 * 
	 * @return {@link StatusAlert} to be processed in case of uncovered POE
	 */
	StatusAlert getAlertOnUncoveredPOE();

	/**
	 * This method allows to change the behavior on expired signature
	 * (if the signing certificate or its POE(s) has been expired).
	 *
	 * Default : {@link ExceptionOnStatusAlert} - throw an exception.
	 *
	 * @param alertOnUncoveredPOE defines a behaviour in case of an expired signature
	 */
	void setAlertOnExpiredSignature(StatusAlert alertOnUncoveredPOE);

	/**
	 * This method returns the defined execution behaviour on expired signature
	 * (if the signing certificate or its POE(s) has been expired).
	 *
	 * @return {@link StatusAlert} to be processed in case of uncovered POE
	 */
	StatusAlert getAlertOnExpiredSignature();

	/**
	 * This method allows enabling of revocation checking for untrusted certificate
	 * chains (default : false)
	 * 
	 * @param enable
	 *               true if revocation checking is allowed for untrusted
	 *               certificate chains
	 */
	void setCheckRevocationForUntrustedChains(boolean enable);

	/**
	 * This method returns true if revocation check is enabled for untrusted
	 * certificate chains.
	 * 
	 * @return true if external revocation check is done for untrusted certificate
	 *         chains
	 */
	boolean isCheckRevocationForUntrustedChains();

}
