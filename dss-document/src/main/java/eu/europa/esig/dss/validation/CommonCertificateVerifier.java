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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.alert.DSSExceptionAlert;
import eu.europa.esig.dss.alert.DSSLogAlert;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;

/**
 * This class provides the different sources used to verify the status of a certificate using the trust model. There are
 * four different types of sources to be defined:<br>
 * - Trusted certificates source;<br>
 * - Adjunct certificates source (not trusted);<br>
 * - OCSP source;<br>
 * - CRL source.<br>
 *
 * The {@code DataLoader} should be provided to give access to the certificates through AIA.
 *
 */
public class CommonCertificateVerifier implements CertificateVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(CommonCertificateVerifier.class);
	
	/**
	 * This field contains the reference to multiple trusted certificate sources. These sources are fixed, it means that the same
	 * sources are used for different validations.
	 */
	private List<CertificateSource> trustedCertSources = new ArrayList<>();

	/**
	 * This field contains the reference to any certificate source, can contain the trust store, or the any intermediate
	 * certificates.
	 */
	private CertificateSource adjunctCertSource;

	/**
	 * This field contains the reference to the {@code OCSPSource}.
	 */
	private RevocationSource<OCSP> ocspSource;

	/**
	 * This field contains the reference to the {@code CRLSource}.
	 */
	private RevocationSource<CRL> crlSource;

	/**
	 * The data loader used to access AIA certificate source.
	 */
	private DataLoader dataLoader;

	/**
	 * This variable contains the {@code ListRevocationSource} extracted from the
	 * signatures to validate.
	 */
	private ListRevocationSource<CRL> signatureCRLSource;

	/**
	 * This variable contains the {@code ListRevocationSource} extracted from the
	 * signatures to validate.
	 */
	private ListRevocationSource<OCSP> signatureOCSPSource;
	
	/**
	 * This variable contains the {@code ListCertificateSource} extracted from the
	 * signatures to validate.
	 */
	private ListCertificateSource signatureCertificateSource;

	/**
	 * This variable set the default Digest Algorithm what will be used for calculation
	 * of digests for validation tokens and signed data
	 * Default: SHA256
	 */
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	/**
	 * This variable set the behavior to include raw certificate tokens into the
	 * diagnostic report. (default: false)
	 */
	private boolean includeCertificateTokens = false;
	
	/**
	 * This variable set the behavior to include raw revocation data into the diagnostic report.
	 * (default: false) 
	 */
	private boolean includeRawRevocationData = false;

	/**
	 * This variable set the behavior to include raw timestamp tokens into the
	 * diagnostic report. (default: false)
	 */
	private boolean includeRawTimestampTokens = false;

	/**
	 * This variable set the behavior to follow in case of invalid timestamp
	 * (augmentation process).
	 * Default : DSSExceptionAlert - throw the exception
	 */
	private Alert<Exception> alertOnInvalidTimestamp = new DSSExceptionAlert();

	/**
	 * This variable set the behavior to follow in case of missing revocation data
	 * (augmentation process).
	 * Default : DSSExceptionAlert - throw the exception
	 */
	private Alert<Exception> alertOnMissingRevocationData = new DSSExceptionAlert();

	/**
	 * This variable set the behavior to follow in case of revoked certificate
	 * (augmentation process). 
	 * Default : DSSExceptionAlert - throw the exception
	 */
	private Alert<Exception> alertOnRevokedCertificate = new DSSExceptionAlert();

	/**
	 * This variable set the behavior to follow in case of no revocation data issued
	 * after the bestSignatureTime (augmentation process). 
	 * Default : DSSLogAlert - log a warning message
	 */
	private Alert<Exception> alertOnNoRevocationAfterBestSignatureTime = new DSSLogAlert(Level.WARN, LOG.isDebugEnabled());

	/**
	 * This variable set the behavior to follow in case of missing revocation data
	 * for a POE.
	 * Default : DSSLogAlert - log a warning message
	 */
	private Alert<Exception> alertOnUncoveredPOE = new DSSLogAlert(Level.WARN, LOG.isDebugEnabled());

	/**
	 * This variable set the behavior to follow for revocation retrieving in case of
	 * untrusted certificate chains. Default : false (revocation are not checked in
	 * case of certificates issued from an unsure source)
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
	 * This constructor allows to create {@code CommonCertificateVerifier} without {@code DataLoader}. It means that
	 * only a profile -B signatures can be created.
	 *
	 * @param simpleCreationOnly
	 *            if true the {@code CommonCertificateVerifier} will not contain {@code DataLoader}.
	 */
	public CommonCertificateVerifier(final boolean simpleCreationOnly) {
		LOG.info("+ New CommonCertificateVerifier created.");
		if (!simpleCreationOnly) {
			dataLoader = new NativeHTTPDataLoader();
		}
	}

	/**
	 * The constructor with key parameters.
	 *
	 * @param trustedCertSources
	 *            the reference to the trusted certificate sources.
	 * @param crlSource
	 *            contains the reference to the {@code OCSPSource}.
	 * @param ocspSource
	 *            contains the reference to the {@code CRLSource}.
	 * @param dataLoader
	 *            contains the reference to a data loader used to access AIA certificate source.
	 */
	public CommonCertificateVerifier(final List<CertificateSource> trustedCertSources, final CRLSource crlSource, final OCSPSource ocspSource,
			final DataLoader dataLoader) {

		LOG.info("+ New CommonCertificateVerifier created with parameters.");
		this.trustedCertSources = trustedCertSources;
		this.crlSource = crlSource;
		this.ocspSource = ocspSource;
		this.dataLoader = dataLoader;
		if (dataLoader == null) {
			LOG.warn("DataLoader is null. It's required to access AIA certificate source");
		}
	}

	@Override
	public List<CertificateSource> getTrustedCertSources() {
		return Collections.unmodifiableList(trustedCertSources);
	}

	@Override
	public RevocationSource<OCSP> getOcspSource() {
		return ocspSource;
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
	public void setOcspSource(final RevocationSource<OCSP> ocspSource) {
		this.ocspSource = ocspSource;
	}

	@Override
	public void setTrustedCertSource(final CertificateSource trustedCertSource) {
		if (CertificateSourceType.TRUSTED_STORE.equals(trustedCertSource.getCertificateSourceType()) ||
				CertificateSourceType.TRUSTED_LIST.equals(trustedCertSource.getCertificateSourceType())) {
			this.trustedCertSources.add(trustedCertSource);
		} else {
			throw new DSSException(String.format("The certificateSource with type [%s] is not allowed in the trustedCertSources. Please, "
					+ "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", trustedCertSource.getCertificateSourceType()));
		}
	}
	
	@Override
	public void setTrustedCertSources(final CertificateSource... certSources) {
		for (CertificateSource source : certSources) {
			setTrustedCertSource(source);
		}
	}
	
	/**
	 * This methods clears the list of defined trusted certificate sources
	 */
	public void clearTrustedCertSources() {
		trustedCertSources.clear();
	}

	@Override
	public CertificateSource getAdjunctCertSource() {
		return adjunctCertSource;
	}

	@Override
	public void setAdjunctCertSource(final CertificateSource adjunctCertSource) {
		if (adjunctCertSource instanceof CommonTrustedCertificateSource) {
			LOG.warn("Adjunct certificate source shouldn't be trusted. This source contains missing intermediate certificates");
		}
		this.adjunctCertSource = adjunctCertSource;
	}

	@Override
	public DataLoader getDataLoader() {
		return dataLoader;
	}

	@Override
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	@Override
	public ListRevocationSource<CRL> getSignatureCRLSource() {
		return signatureCRLSource;
	}

	@Override
	public void setSignatureCRLSource(final ListRevocationSource<CRL> signatureCRLSource) {
		this.signatureCRLSource = signatureCRLSource;
	}

	@Override
	public ListRevocationSource<OCSP> getSignatureOCSPSource() {
		return signatureOCSPSource;
	}

	@Override
	public void setSignatureOCSPSource(final ListRevocationSource<OCSP> signatureOCSPSource) {
		this.signatureOCSPSource = signatureOCSPSource;
	}

	@Override
	public ListCertificateSource getSignatureCertificateSource() {
		return signatureCertificateSource;
	}

	@Override
	public void setSignatureCertificateSource(ListCertificateSource signatureCertificateSource) {
		this.signatureCertificateSource = signatureCertificateSource;
	}

	@Override
	public Alert<Exception> getAlertOnInvalidTimestamp() {
		return alertOnInvalidTimestamp;
	}

	@Override
	public void setAlertOnInvalidTimestamp(Alert<Exception> alertOnInvalidTimestamp) {
		this.alertOnInvalidTimestamp = alertOnInvalidTimestamp;
	}

	@Override
	public void setAlertOnMissingRevocationData(Alert<Exception> alertOnMissingRevocationData) {
		this.alertOnMissingRevocationData = alertOnMissingRevocationData;
	}

	@Override
	public Alert<Exception> getAlertOnMissingRevocationData() {
		return alertOnMissingRevocationData;
	}

	@Override
	public Alert<Exception> getAlertOnUncoveredPOE() {
		return alertOnUncoveredPOE;
	}

	@Override
	public void setAlertOnUncoveredPOE(Alert<Exception> alertOnUncoveredPOE) {
		this.alertOnUncoveredPOE = alertOnUncoveredPOE;
	}

	@Override
	public Alert<Exception> getAlertOnRevokedCertificate() {
		return alertOnRevokedCertificate;
	}

	@Override
	public void setAlertOnRevokedCertificate(Alert<Exception> alertOnRevokedCertificate) {
		this.alertOnRevokedCertificate = alertOnRevokedCertificate;
	}

	@Override
	public Alert<Exception> getAlertOnNoRevocationAfterBestSignatureTime() {
		return alertOnNoRevocationAfterBestSignatureTime;
	}

	@Override
	public void setAlertOnNoRevocationAfterBestSignatureTime(Alert<Exception> alertOnNoRevocationAfterBestSignatureTime) {
		this.alertOnNoRevocationAfterBestSignatureTime = alertOnNoRevocationAfterBestSignatureTime;
	}

	@Override
	public boolean isCheckRevocationForUntrustedChains() {
		return checkRevocationForUntrustedChains;
	}

	@Override
	public void setCheckRevocationForUntrustedChains(boolean checkRevocationForUntrustedChains) {
		this.checkRevocationForUntrustedChains = checkRevocationForUntrustedChains;
	}

	@Override
	public void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.defaultDigestAlgorithm = digestAlgorithm;
	}
	
	@Override
	public DigestAlgorithm getDefaultDigestAlgorithm() {
		return defaultDigestAlgorithm;
	}

	@Override
	public void setIncludeCertificateTokenValues(boolean includeCertificateTokens) {
		this.includeCertificateTokens = includeCertificateTokens;
	}

	@Override
	public boolean isIncludeCertificateTokenValues() {
		return includeCertificateTokens;
	}

	@Override
	public void setIncludeCertificateRevocationValues(boolean include) {
		this.includeRawRevocationData = include;
	}

	@Override
	public boolean isIncludeCertificateRevocationValues() {
		return this.includeRawRevocationData;
	}

	@Override
	public void setIncludeTimestampTokenValues(boolean include) {
		this.includeRawTimestampTokens = include;
	}

	@Override
	public boolean isIncludeTimestampTokenValues() {
		return this.includeRawTimestampTokens;
	}

}
