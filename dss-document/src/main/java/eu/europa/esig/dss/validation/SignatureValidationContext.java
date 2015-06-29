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

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * During the validation of a signature, the software retrieves different X509 artifacts like Certificate, CRL and OCSP Response. The SignatureValidationContext is a "cache" for
 * one validation request that contains every object retrieved so far.
 *
 */
public class SignatureValidationContext implements ValidationContext {

	private static final Logger logger = LoggerFactory.getLogger(SignatureValidationContext.class);

	private final Set<CertificateToken> processedCertificates = new HashSet<CertificateToken>();
	private final Set<RevocationToken> processedRevocations = new HashSet<RevocationToken>();
	private final Set<TimestampToken> processedTimestamps = new HashSet<TimestampToken>();

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
			throw new NullPointerException();
		}
		this.validationCertificatePool = validationCertificatePool;
	}

	/**
	 * @param certificateVerifier The certificates verifier (eg: using the TSL as list of trusted certificates).
	 */
	@Override
	public void initialize(final CertificateVerifier certificateVerifier) {
		if (certificateVerifier == null) {
			throw new NullPointerException();
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

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public void setCurrentTime(final Date currentTime) {
		if (currentTime == null) {
			throw new NullPointerException();
		}
		this.currentTime = currentTime;
	}

	/**
	 * This method returns a token to verify. If there is no more tokens to verify null is returned.
	 *
	 * @return token to verify or null
	 */
	private Token getNotYetVerifiedToken() {
		synchronized (tokensToProcess) {
			for (final Entry<Token, Boolean> entry : tokensToProcess.entrySet()) {

				if (entry.getValue() == null) {

					entry.setValue(true);
					return entry.getKey();
				}
			}
			return null;
		}
	}

	/**
	 * This method returns the issuer certificate (the certificate which was used to sign the token) of the given token.
	 *
	 * @param token the token for which the issuer must be obtained.
	 * @return the issuer certificate token of the given token or null if not found.
	 * @throws eu.europa.esig.dss.DSSException
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

		if ((issuerCertificateToken == null) && (token instanceof CertificateToken)) {

			issuerCertificateToken = getIssuerFromAIA((CertificateToken) token);
		}
		if (issuerCertificateToken == null) {

			token.extraInfo().infoTheSigningCertNotFound();
		}
		if ((issuerCertificateToken != null) && !issuerCertificateToken.isTrusted() && !issuerCertificateToken.isSelfSigned()) {

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

		final CertificateToken issuerCert;
		try {

			logger.info("Retrieving {} certificate's issuer using AIA.", token.getAbbreviation());
			issuerCert = DSSUtils.loadIssuerCertificate(token, dataLoader);
			if (issuerCert != null) {

				final CertificateToken issuerCertToken = validationCertificatePool.getInstance(issuerCert, CertificateSourceType.AIA);
				if (token.isSignedBy(issuerCertToken)) {

					return issuerCertToken;
				}
				logger.info("The retrieved certificate using AIA does not sign the certificate {}.", token.getAbbreviation());
			} else {

				logger.info("The issuer certificate cannot be loaded using AIA.");
			}
		} catch (DSSException e) {

			logger.error(e.getMessage());
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

		final boolean traceEnabled = logger.isTraceEnabled();
		synchronized (tokensToProcess) {

			if (traceEnabled) {
				logger.trace("addTokenForVerification: trying to acquire synchronized block");
			}
			try {

				if (token == null) {
					return false;
				}
				if (tokensToProcess.containsKey(token)) {

					if (traceEnabled) {
						logger.trace("Token was already in the list {}:{}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation()});
					}
					return false;
				}
				tokensToProcess.put(token, null);
				if (traceEnabled) {
					logger.trace("+ New {} to check: {}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation()});
				}
				return true;
			} finally {
				if (traceEnabled) {
					logger.trace("addTokenForVerification: almost left synchronized block");
				}
			}
		}
	}

	@Override
	public void addRevocationTokenForVerification(final RevocationToken revocationToken) {

		if (addTokenForVerification(revocationToken)) {

			final boolean added = processedRevocations.add(revocationToken);
			if (logger.isTraceEnabled()) {
				if (added) {
					logger.trace("RevocationToken added to processedRevocations: {} ", revocationToken);
				} else {
					logger.trace("RevocationToken already present processedRevocations: {} ", revocationToken);
				}
			}
		}
	}

	@Override
	public void addCertificateTokenForVerification(final CertificateToken certificateToken) {

		if (addTokenForVerification(certificateToken)) {

			final boolean added = processedCertificates.add(certificateToken);
			if (logger.isTraceEnabled()) {
				if (added) {
					logger.trace("CertificateToken added to processedRevocations: {} ", certificateToken);
				} else {
					logger.trace("CertificateToken already present processedRevocations: {} ", certificateToken);
				}
			}
		}
	}

	@Override
	public void addTimestampTokenForVerification(final TimestampToken timestampToken) {

		if (addTokenForVerification(timestampToken)) {

			final boolean added = processedTimestamps.add(timestampToken);
			if (logger.isTraceEnabled()) {
				if (added) {
					logger.trace("TimestampToken added to processedRevocations: {} ", processedTimestamps);
				} else {
					logger.trace("TimestampToken already present processedRevocations: {} ", processedTimestamps);
				}
			}
		}
	}

	@Override
	public void validate() throws DSSException {
		Token token = null;
		do {
			token = getNotYetVerifiedToken();
			if (token != null) {

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

			}
		} while (token != null);
	}

	/**
	 * Retrieves the revocation data from signature (if exists) or from the online sources. The issuer certificate must be provided, the underlining library (bouncy castle) needs
	 * it to build the request.
	 *
	 * @param certToken
	 * @return
	 */
	private RevocationToken getRevocationData(final CertificateToken certToken) {

		if (logger.isTraceEnabled()) {
			logger.trace("Checking revocation data for: " + certToken.getDSSIdAsString());
		}
		if (certToken.isSelfSigned() || certToken.isTrusted() || (certToken.getIssuerToken() == null)) {

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
					if ((date != null) && date.before(notAfter)) {

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
