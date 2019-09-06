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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;

/**
 * This class provides the different sources used to verify the status of a certificate using the trust model. There are
 * four different types of sources to be defined:<br>
 * -
 * Trusted certificates source;<br>
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
	 * This field contains the reference to the trusted certificate source. This source is fixed, it means that the same
	 * source is used for different validations.
	 */
	private CertificateSource trustedCertSource;

	/**
	 * This field contains the reference to any certificate source, can contain the trust store, or the any intermediate
	 * certificates.
	 */
	private CertificateSource adjunctCertSource;

	/**
	 * This field contains the reference to the {@code OCSPSource}.
	 */
	private OCSPSource ocspSource;

	/**
	 * This field contains the reference to the {@code CRLSource}.
	 */
	private CRLSource crlSource;

	/**
	 * The data loader used to access AIA certificate source.
	 */
	private DataLoader dataLoader;

	/**
	 * This variable contains the {@code ListCRLSource} extracted from the signatures to validate.
	 */
	private ListCRLSource signatureCRLSource;

	/**
	 * This variable contains the {@code ListOCSPSource} extracted from the signatures to validate.
	 */
	private ListOCSPSource signatureOCSPSource;

	/**
	 * This variable set the behavior to follow in case of missing revocation data
	 * (augmentation process). True : throw an exception / False : add a warning
	 * message. Default : true
	 */
	private boolean exceptionOnMissingRevocationData = true;

	/**
	 * This variable set the behavior to follow in case of missing revocation data
	 * for a POE. True : throw an exception / False : add a warning message. Default
	 * : false
	 */
	private boolean exceptionOnUncoveredPOE = false;
	
	/**
	 * This variable set the default Digest Algorithm what will be used for calculation
	 * of digests for validation tokns and signed data
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
	 * This variable set the behavior to follow in case of revoked certificate
	 * (augmentation process). True : throw an exception / False : add a warning
	 * message. Default : true
	 */
	private boolean exceptionOnRevokedCertificate = true;

	/**
	 * This variable set the behavior to follow in case of invalid timestamp
	 * (augmentation process). True : throw an exception / False : add a warning
	 * message. Default : true
	 */
	private boolean exceptionOnInvalidTimestamp = true;

	/**
	 * This variable set the behavior to follow in case of no revocation data issued
	 * after the bestSignatureTime (augmentation process). 
	 * True : throw an exception / False : add a warning message. Default : false
	 */
	private boolean exceptionOnNoRevocationAfterBestSignatureTime = false;

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
	 * @param trustedCertSource
	 *            the reference to the trusted certificate source.
	 * @param crlSource
	 *            contains the reference to the {@code OCSPSource}.
	 * @param ocspSource
	 *            contains the reference to the {@code CRLSource}.
	 * @param dataLoader
	 *            contains the reference to a data loader used to access AIA certificate source.
	 */
	public CommonCertificateVerifier(final CertificateSource trustedCertSource, final CRLSource crlSource, final OCSPSource ocspSource,
			final DataLoader dataLoader) {

		LOG.info("+ New CommonCertificateVerifier created with parameters.");
		this.trustedCertSource = trustedCertSource;
		this.crlSource = crlSource;
		this.ocspSource = ocspSource;
		this.dataLoader = dataLoader;
		if (dataLoader == null) {
			LOG.warn("DataLoader is null. It's required to access AIA certificate source");
		}
	}

	@Override
	public CertificateSource getTrustedCertSource() {
		return trustedCertSource;
	}

	@Override
	public OCSPSource getOcspSource() {
		return ocspSource;
	}

	@Override
	public CRLSource getCrlSource() {
		return crlSource;
	}

	@Override
	public void setCrlSource(final CRLSource crlSource) {
		this.crlSource = crlSource;
	}

	@Override
	public void setOcspSource(final OCSPSource ocspSource) {
		this.ocspSource = ocspSource;
	}

	@Override
	public void setTrustedCertSource(final CertificateSource trustedCertSource) {
		this.trustedCertSource = trustedCertSource;
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
	public ListCRLSource getSignatureCRLSource() {
		return signatureCRLSource;
	}

	@Override
	public void setSignatureCRLSource(final ListCRLSource signatureCRLSource) {
		this.signatureCRLSource = signatureCRLSource;
	}

	@Override
	public ListOCSPSource getSignatureOCSPSource() {
		return signatureOCSPSource;
	}

	@Override
	public void setSignatureOCSPSource(final ListOCSPSource signatureOCSPSource) {
		this.signatureOCSPSource = signatureOCSPSource;
	}

	@Override
	public void setExceptionOnMissingRevocationData(boolean throwExceptionOnMissingRevocationData) {
		this.exceptionOnMissingRevocationData = throwExceptionOnMissingRevocationData;
	}

	@Override
	public boolean isExceptionOnMissingRevocationData() {
		return exceptionOnMissingRevocationData;
	}

	@Override
	public boolean isExceptionOnUncoveredPOE() {
		return exceptionOnUncoveredPOE;
	}

	@Override
	public void setExceptionOnUncoveredPOE(boolean exceptionOnUncoveredPOE) {
		this.exceptionOnUncoveredPOE = exceptionOnUncoveredPOE;
	}

	@Override
	public boolean isExceptionOnRevokedCertificate() {
		return exceptionOnRevokedCertificate;
	}

	@Override
	public void setExceptionOnRevokedCertificate(boolean exceptionOnRevokedCertificate) {
		this.exceptionOnRevokedCertificate = exceptionOnRevokedCertificate;
	}

	@Override
	public void setExceptionOnInvalidTimestamp(boolean throwExceptionOnInvalidTimestamp) {
		this.exceptionOnInvalidTimestamp = throwExceptionOnInvalidTimestamp;
	}

	@Override
	public boolean isExceptionOnInvalidTimestamp() {
		return exceptionOnInvalidTimestamp;
	}

	@Override
	public void setExceptionOnNoRevocationAfterBestSignatureTime(boolean exceptionOnNoRevocationAfterBestSignatureTime) {
		this.exceptionOnNoRevocationAfterBestSignatureTime = exceptionOnNoRevocationAfterBestSignatureTime;
	}

	@Override
	public boolean isExceptionOnNoRevocationAfterBestSignatureTime() {
		return exceptionOnNoRevocationAfterBestSignatureTime;
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
	public CertificatePool createValidationPool() {
		final CertificatePool validationPool = new CertificatePool();
		if (trustedCertSource != null) {
			validationPool.importCerts(trustedCertSource);
		}
		if (adjunctCertSource != null) {
			validationPool.importCerts(adjunctCertSource);
		}
		return validationPool;
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
