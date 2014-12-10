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

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.crl.CRLSource;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPSource;

/**
 * During the validation of a signature, the software retrieves different X509 artifacts like Certificate, CRL and OCSP Response. The SignatureValidationContext is a "cache" for
 * one validation request that contains every object retrieved so far.
 * <p/>
 * The validate method is multi-threaded, using an CachedThreadPool from ExecutorService, to parallelize fetching of the certificates from AIA and of the revocation information
 * from online sources.
 *
 * @version $Revision: 1839 $ - $Date: 2013-04-04 17:40:51 +0200 (Thu, 04 Apr 2013) $
 */

public class SignatureValidationContext implements ValidationContext {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureValidationContext.class);

	/**
	 * Each unit is approximately 5 seconds
	 */
	public static int MAX_TIMEOUT = 5;

	private final Set<CertificateToken> processedCertificates = new HashSet<CertificateToken>();
	private final Set<RevocationToken> processedRevocations = new HashSet<RevocationToken>();

	private final Set<TimestampToken> processedTimestamps = new HashSet<TimestampToken>();

	static int threadCount = 0;

	/**
	 * The data loader used to access AIA certificate source.
	 */
	private DataLoader dataLoader;

	/**
	 * The certificate pool which encapsulates all certificates used during the validation process and extracted from all used sources
	 */
	protected CertificatePool validationCertificatePool;

	private final Map<Token, Boolean> tokensToProcess = new HashMap<Token, Boolean>();

	// External OCSP source.
	private OCSPSource ocspSource;

	// External CRL source.
	private CRLSource crlSource;

	// CRLs from the signature.
	private CRLSource signatureCRLSource;

	// OCSP from the signature.
	private OCSPSource signatureOCSPSource;

	// The digest value of the certification path references and the revocation status references.
	private List<TimestampReference> timestampedReferences;

	/**
	 * This is the time at what the validation is carried out. It is used only for test purpose.
	 */
	protected Date currentTime = new Date();

	/**
	 * A unique thread can be used to disable the parallel fetching:
	 */
	//	private final ExecutorService executorService = Executors.newFixedThreadPool(1);
	private final ExecutorService executorService = Executors.newCachedThreadPool();

	/**
	 * This constructor is used during the signature creation process. The certificate pool is created within initialize method.
	 */
	public SignatureValidationContext() {

	}

	/**
	 * This constructor is used when a signature need to be validated.
	 *
	 * @param validationCertificatePool The pool of certificates used during the validation process
	 */
	public SignatureValidationContext(final CertificatePool validationCertificatePool) {

		if (validationCertificatePool == null) {
			throw new DSSNullException(CertificatePool.class);
		}
		this.validationCertificatePool = validationCertificatePool;
	}

	/**
	 * @param certificateVerifier The certificates verifier (eg: using the TSL as list of trusted certificates).
	 */
	@Override
	public void initialize(final CertificateVerifier certificateVerifier) {

		if (certificateVerifier == null) {
			throw new DSSNullException(CertificateVerifier.class);
		}
		if (validationCertificatePool == null) {

			validationCertificatePool = certificateVerifier.createValidationPool();
		}
		this.crlSource = certificateVerifier.getCrlSource();
		this.ocspSource = certificateVerifier.getOcspSource();
		this.dataLoader = certificateVerifier.getDataLoader();
		this.signatureCRLSource = certificateVerifier.getSignatureCRLSource();
		this.signatureOCSPSource = certificateVerifier.getSignatureOCSPSource();
	}

	public Date getCurrentTime() {
		return currentTime;
	}

	public void setCurrentTime(final Date currentTime) throws DSSException {

		if (currentTime == null) {
			throw new DSSNullException(Date.class, "currentTime");
		}
		this.currentTime = currentTime;
	}

	/**
	 * This method returns a token to verify. If there is no more tokens to verify null is returned.
	 *
	 * @return token to verify or null
	 */
	private Token getNotYetVerifiedToken() {
		//		LOG.debug("getNotYetVerifiedToken: trying to acquire synchronized block");
		synchronized (tokensToProcess) {
			//			LOG.debug("getNotYetVerifiedToken: acquired synchronized block");
			for (final Entry<Token, Boolean> entry : tokensToProcess.entrySet()) {

				if (entry.getValue() == null) {

					entry.setValue(true);
					return entry.getKey();
				}
			}
			//			LOG.debug("getNotYetVerifiedToken: almost left synchronized block");
			return null;
		}
	}

	/**
	 * This method returns the issuer certificate (the certificate which was used to sign the token) of the given token.
	 *
	 * @param token the token for which the issuer must be obtained.
	 * @return the issuer certificate token of the given token or null if not found.
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private CertificateToken getIssuerCertificate(final Token token) throws DSSException {

		if (token.isTrusted()) {

			// When the token is trusted the check of the issuer token is not needed so null is returned. Only a certificate token can be trusted.
			return null;
		}
		if (token.getIssuerToken() != null) {

			/**
			 * The signer's certificate have been found already. This can happen in the case of:<br>
			 * - multiple signatures that use the same certificate,<br>
			 * - OCSPRespTokens (the issuer certificate is known from the beginning)
			 */
			return token.getIssuerToken();
		}
		final X500Principal issuerX500Principal = token.getIssuerX500Principal();
		CertificateToken issuerCertificateToken = getIssuerFromPool(token, issuerX500Principal);

		if (issuerCertificateToken == null && token instanceof CertificateToken) {

			issuerCertificateToken = getIssuerFromAIA((CertificateToken) token);
		}
		if (issuerCertificateToken == null) {

			token.extraInfo().infoTheSigningCertNotFound();
		}
		if (issuerCertificateToken != null && !issuerCertificateToken.isTrusted() && !issuerCertificateToken.isSelfSigned()) {

			// The full chain is retrieved for each certificate
			getIssuerCertificate(issuerCertificateToken);
		}
		return issuerCertificateToken;
	}

	/**
	 * Get the issuer's certificate from Authority Information Access through id-ad-caIssuers extension.
	 *
	 * @param token {@code CertificateToken} for which the issuer is sought.
	 * @return {@code CertificateToken} representing the issuer certificate or null.
	 */
	private CertificateToken getIssuerFromAIA(final CertificateToken token) {

		final X509Certificate issuerCert;
		try {

			LOG.info("Retrieving {} certificate's issuer using AIA.", token.getAbbreviation());
			issuerCert = DSSUtils.loadIssuerCertificate(token.getCertificate(), dataLoader);
			if (issuerCert != null) {

				final CertificateToken issuerCertToken = validationCertificatePool.getInstance(issuerCert, CertificateSourceType.AIA);
				if (token.isSignedBy(issuerCertToken)) {

					return issuerCertToken;
				}
				LOG.info("The retrieved certificate using AIA does not sign the certificate {}.", token.getAbbreviation());
			} else {

				LOG.info("The issuer certificate cannot be loaded using AIA.");
			}
		} catch (DSSException e) {

			LOG.error(e.getMessage());
		}
		return null;
	}

	/**
	 * This function retrieves the issuer certificate from the validation pool (this pool should contain trusted certificates). The check is made if the token is well signed by
	 * the retrieved certificate.
	 *
	 * @param token               token for which the issuer have to be found
	 * @param issuerX500Principal issuer's subject distinguished name
	 * @return the corresponding {@code CertificateToken} or null if not found
	 */
	private CertificateToken getIssuerFromPool(final Token token, final X500Principal issuerX500Principal) {

		final List<CertificateToken> issuerCertList = validationCertificatePool.get(issuerX500Principal);
		for (final CertificateToken issuerCertToken : issuerCertList) {

			// We keep the first issuer that signs the certificate
			if (token.isSignedBy(issuerCertToken)) {

				return issuerCertToken;
			}
		}
		return null;
	}

	/**
	 * Adds a new token to the list of tokes to verify only if it was not already verified.
	 *
	 * @param token token to verify
	 * @return true if the token was not yet verified, false otherwise.
	 */
	private boolean addTokenForVerification(final Token token) {

		final boolean traceEnabled = LOG.isTraceEnabled();
		synchronized (tokensToProcess) {

			if (traceEnabled) {
				LOG.trace("addTokenForVerification: trying to acquire synchronized block");
			}
			try {

				if (token == null) {
					return false;
				}
				if (tokensToProcess.containsKey(token)) {

					if (traceEnabled) {
						LOG.trace("Token was already in the list {}:{}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation()});
					}
					return false;
				}
				tokensToProcess.put(token, null);
				if (traceEnabled) {
					LOG.trace("+ New {} to check: {}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation()});
				}
				return true;
			} finally {
				if (traceEnabled) {
					LOG.trace("addTokenForVerification: almost left synchronized block");
				}
			}
		}
	}

	@Override
	public void addRevocationTokenForVerification(final RevocationToken revocationToken) {

		if (addTokenForVerification(revocationToken)) {

			final boolean added = processedRevocations.add(revocationToken);
			if (LOG.isTraceEnabled()) {
				if (added) {
					LOG.trace("RevocationToken added to processedRevocations: {} ", revocationToken);
				} else {
					LOG.trace("RevocationToken already present processedRevocations: {} ", revocationToken);
				}
			}
		}
	}

	@Override
	public void addCertificateTokenForVerification(final CertificateToken certificateToken) {

		if (addTokenForVerification(certificateToken)) {

			final boolean added = processedCertificates.add(certificateToken);
			if (LOG.isTraceEnabled()) {
				if (added) {
					LOG.trace("CertificateToken added to processedRevocations: {} ", certificateToken);
				} else {
					LOG.trace("CertificateToken already present processedRevocations: {} ", certificateToken);
				}
			}
		}
	}

	@Override
	public void addTimestampTokenForVerification(final TimestampToken timestampToken) {

		if (addTokenForVerification(timestampToken)) {

			final boolean added = processedTimestamps.add(timestampToken);
			if (LOG.isTraceEnabled()) {
				if (added) {
					LOG.trace("TimestampToken added to processedRevocations: {} ", processedTimestamps);
				} else {
					LOG.trace("TimestampToken already present processedRevocations: {} ", processedTimestamps);
				}
			}
		}
	}

	@Override
	public void validate() throws DSSException {

		validateLoop();
		try {

			LOG.debug(">>> MT ***DONE***");
			executorService.shutdown();
			executorService.awaitTermination(5, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	private void validateLoop() {

		int threshold = 0;
		int max_timeout = 0;
		final ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) executorService;
		boolean exit = false;
		boolean checkAgain = true;
		do {

			final Token token = getNotYetVerifiedToken();
			if (token != null) {

				checkAgain = true;
				try {

					//					System.out.println("----------------------------------------------------");
					//					System.out.println(" DSS_ID: " + token.getDSSId());
					//					System.out.println("----------------------------------------------------");
					final Task task = new Task(token);
					executorService.submit(task);
				} catch (RejectedExecutionException e) {
					LOG.error(e.getMessage(), e);
					throw new DSSException(e);
				}
			} else {

				try {

					Thread.sleep(5);
					threshold++;
					if (threshold > 1000) {

						LOG.warn("{} active threads", threadPoolExecutor.getActiveCount());
						LOG.warn("{} completed tasks", threadPoolExecutor.getCompletedTaskCount());
						LOG.warn("{} waiting tasks", threadPoolExecutor.getQueue());
						max_timeout++;
						if (max_timeout == MAX_TIMEOUT) {
							throw new DSSException("Operation aborted, the retrieval of the validation data takes too long.");
						}
						threshold = 0;
					}
				} catch (InterruptedException e) {
					throw new DSSException(e);
				}
				final boolean threadPoolExecutorEmpty = !(threadPoolExecutor.getActiveCount() > 0 || threadPoolExecutor.getQueue().size() > 0);
				exit = threadPoolExecutorEmpty && !checkAgain;
				if (threadPoolExecutorEmpty) {
					checkAgain = false;
				}
			}
		} while (!exit);

	}

	class Task implements Runnable {

		private final Token token;

		public Task(final Token token) {

			this.token = token;
		}

		@Override
		public void run() {

			final int threadCount_ = threadCount++;
			LOG.debug(">>> MT IN  [" + threadCount_ + "] DSS_ID: " + token.getDSSId());
			/**
			 * Gets the issuer certificate of the Token and checks its signature
			 */
			final CertificateToken issuerCertToken = getIssuerCertificate(token);
			if (issuerCertToken != null) {

				addCertificateTokenForVerification(issuerCertToken);
			}
			if (token instanceof CertificateToken) {

				final RevocationToken revocationToken = getRevocationData((CertificateToken) token);
				addRevocationTokenForVerification(revocationToken);
			}
			LOG.debug(">>> MT END [" + threadCount_ + "] DSS_ID: " + token.getDSSId());
		}
	}

	/**
	 * Retrieves the revocation data from signature (if exists) or from the online sources. The issuer certificate must be provided, the underlining library (bouncy castle) needs
	 * it to build the request. This feature has an impact on the multi-threaded data retrieval.
	 *
	 * @param certToken
	 * @return
	 */
	private RevocationToken getRevocationData(final CertificateToken certToken) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("Checking revocation data for: " + certToken.getDSSIdAsString());
		}
		if (certToken.isSelfSigned() || certToken.isTrusted() || certToken.getIssuerToken() == null) {

			// It is not possible to check the revocation data without its signing certificate;
			// This check is not needed for the trust anchor.
			return null;
		}

		if (certToken.isOCSPSigning() && certToken.hasIdPkixOcspNoCheckExtension()) {

			certToken.extraInfo().add("OCSP check not needed: id-pkix-ocsp-nocheck extension present.");
			return null;
		}

		boolean checkOnLine = shouldCheckOnLine(certToken);
		if (checkOnLine) {

			final OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier(crlSource, ocspSource, validationCertificatePool);
			final RevocationToken revocationToken = onlineVerifier.check(certToken);
			if (revocationToken != null) {

				return revocationToken;
			}
		}
		final OCSPAndCRLCertificateVerifier offlineVerifier = new OCSPAndCRLCertificateVerifier(signatureCRLSource, signatureOCSPSource, validationCertificatePool);
		final RevocationToken revocationToken = offlineVerifier.check(certToken);
		return revocationToken;
	}

	private boolean shouldCheckOnLine(final CertificateToken certificateToken) {

		final boolean expired = certificateToken.isExpiredOn(currentTime);
		if (!expired) {

			return true;
		}
		final CertificateToken issuerCertToken = certificateToken.getIssuerToken();
		// issuerCertToken cannot be null
		final boolean expiredCertOnCRLExtension = issuerCertToken.hasExpiredCertOnCRLExtension();
		if (expiredCertOnCRLExtension) {

			certificateToken.extraInfo().add("Certificate is expired but the issuer certificate has ExpiredCertOnCRL extension.");
			return true;
		}
		final Date expiredCertsRevocationFromDate = getExpiredCertsRevocationFromDate(certificateToken);
		if (expiredCertsRevocationFromDate != null) {

			certificateToken.extraInfo().add("Certificate is expired but the TSL extension 'expiredCertsRevocationInfo' is present: " + expiredCertsRevocationFromDate);
			return true;
		}
		return false;
	}

	private Date getExpiredCertsRevocationFromDate(final CertificateToken certificateToken) {

		final CertificateToken trustAnchor = certificateToken.getTrustAnchor();
		if (trustAnchor != null) {

			final List<ServiceInfo> serviceInfoList = trustAnchor.getAssociatedTSPS();
			if (serviceInfoList != null) {

				final Date notAfter = certificateToken.getNotAfter();
				for (final ServiceInfo serviceInfo : serviceInfoList) {

					final Date date = serviceInfo.getExpiredCertsRevocationInfo();
					if (date != null && date.before(notAfter)) {

						if (serviceInfo.getStatusEndDate() == null) {

							/**
							 * Service is still active (operational)
							 */
							// if(serviceInfo.getStatus().equals())
							return date;
						}
					}
				}
			}
		}
		return null;
	}

	@Override
	public Set<CertificateToken> getProcessedCertificates() {

		return Collections.unmodifiableSet(processedCertificates);
	}

	@Override
	public Set<RevocationToken> getProcessedRevocations() {

		return Collections.unmodifiableSet(processedRevocations);
	}

	@Override
	public Set<TimestampToken> getProcessedTimestamps() {

		return Collections.unmodifiableSet(processedTimestamps);
	}

	/**
	 * Returns certificate and revocation references.
	 *
	 * @return
	 */
	public List<TimestampReference> getTimestampedReferences() {
		return timestampedReferences;
	}

	/**
	 * This method returns the human readable representation of the ValidationContext.
	 *
	 * @param indentStr
	 * @return
	 */

	public String toString(String indentStr) {

		try {

			final StringBuilder builder = new StringBuilder();
			builder.append(indentStr).append("ValidationContext[").append('\n');
			indentStr += "\t";
			// builder.append(indentStr).append("Validation time:").append(validationDate).append('\n');
			builder.append(indentStr).append("Certificates[").append('\n');
			indentStr += "\t";
			for (CertificateToken certToken : processedCertificates) {

				builder.append(certToken.toString(indentStr));
			}
			indentStr = indentStr.substring(1);
			builder.append(indentStr).append("],\n");
			indentStr = indentStr.substring(1);
			builder.append(indentStr).append("],\n");
			return builder.toString();
		} catch (Exception e) {

			return super.toString();
		}
	}

	@Override
	public String toString() {

		return toString("");
	}
}
