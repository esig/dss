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

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.RevocationSource;
import eu.europa.esig.dss.x509.RevocationSourceAlternateUrlsSupport;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

/**
 * During the validation of a signature, the software retrieves different X509 artifacts like Certificate, CRL and OCSP
 * Response. The SignatureValidationContext is a "cache" for
 * one validation request that contains every object retrieved so far.
 *
 */
public class SignatureValidationContext implements ValidationContext {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureValidationContext.class);

	private final Set<CertificateToken> processedCertificates = new HashSet<CertificateToken>();
	private final Set<RevocationToken> processedRevocations = new HashSet<RevocationToken>();
	private final Set<TimestampToken> processedTimestamps = new HashSet<TimestampToken>();

	/**
	 * The data loader used to access AIA certificate source.
	 */
	private DataLoader dataLoader;

	/**
	 * The certificate pool which encapsulates all certificates used during the validation process and extracted from
	 * all used sources
	 */
	protected CertificatePool validationCertificatePool;

	private final Map<Token, Boolean> tokensToProcess = new HashMap<Token, Boolean>();

	private final Map<Token, Date> lastUsageDates = new HashMap<Token, Date>();

	// External OCSP source.
	private OCSPSource ocspSource;

	// External CRL source.
	private CRLSource crlSource;

	// CRLs from the signature.
	private CRLSource signatureCRLSource;

	// OCSP from the signature.
	private OCSPSource signatureOCSPSource;

	private CertificateSource trustedCertSource;

	/**
	 * This variable set the behavior to follow for revocation retrieving in case of
	 * untrusted certificate chains.
	 */
	private boolean checkRevocationForUntrustedChains;

	/**
	 * This is the time at what the validation is carried out. It is used only for test purpose.
	 */
	protected Date currentTime = new Date();

	/**
	 * This constructor is used during the signature creation process. The certificate pool is created within initialize
	 * method.
	 */
	public SignatureValidationContext() {
	}

	/**
	 * This constructor is used when a signature need to be validated.
	 *
	 * @param validationCertificatePool
	 *            The pool of certificates used during the validation process
	 */
	public SignatureValidationContext(final CertificatePool validationCertificatePool) {
		Objects.requireNonNull(validationCertificatePool);
		this.validationCertificatePool = validationCertificatePool;
	}

	/**
	 * @param certificateVerifier
	 *            The certificates verifier (eg: using the TSL as list of trusted certificates).
	 */
	@Override
	public void initialize(final CertificateVerifier certificateVerifier) {
		Objects.requireNonNull(certificateVerifier);

		if (validationCertificatePool == null) {
			validationCertificatePool = new CertificatePool();
		}

		if (certificateVerifier.getTrustedCertSource() != null) {
			validationCertificatePool.importCerts(certificateVerifier.getTrustedCertSource());
		}
		if (certificateVerifier.getAdjunctCertSource() != null) {
			validationCertificatePool.importCerts(certificateVerifier.getAdjunctCertSource());
		}

		this.crlSource = certificateVerifier.getCrlSource();
		this.ocspSource = certificateVerifier.getOcspSource();
		this.dataLoader = certificateVerifier.getDataLoader();
		this.signatureCRLSource = certificateVerifier.getSignatureCRLSource();
		this.signatureOCSPSource = certificateVerifier.getSignatureOCSPSource();
		this.trustedCertSource = certificateVerifier.getTrustedCertSource();
		this.checkRevocationForUntrustedChains = certificateVerifier.isCheckRevocationForUntrustedChains();
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public void setCurrentTime(final Date currentTime) {
		Objects.requireNonNull(currentTime);
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
	 * This method builds the complete certificate chain from the given token.
	 *
	 * @param token
	 *              the token for which the certificate chain must be obtained.
	 * @return the built certificate chain
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private List<Token> getCertChain(final Token token) throws DSSException {
		List<Token> chain = new LinkedList<Token>();
		Token issuerCertificateToken = token;
		do {
			chain.add(issuerCertificateToken);
			if (isTrusted(issuerCertificateToken)) {
				break;
			}

			issuerCertificateToken = validationCertificatePool.getIssuer(issuerCertificateToken);

			if ((issuerCertificateToken == null) && (token instanceof CertificateToken)) {
				issuerCertificateToken = getIssuerFromAIA((CertificateToken) token);
			}

			if ((issuerCertificateToken == null) && (token instanceof TimestampToken)) {
				issuerCertificateToken = getTSACertificate((TimestampToken) token);
			}

			if (issuerCertificateToken instanceof CertificateToken) {
				addCertificateTokenForVerification((CertificateToken) issuerCertificateToken);
			}

		} while (issuerCertificateToken != null && !chain.contains(issuerCertificateToken));

		return chain;
	}

	private CertificateToken getTSACertificate(TimestampToken timestamp) {
		List<CertificateToken> candidates = timestamp.getCertificates();
		for (CertificateToken candidate : candidates) {
			if (timestamp.isSignedBy(candidate)) {
				return candidate;
			}
		}

		LOG.info("TSA certificate not found in the token");

		candidates = validationCertificatePool.getBySignerId(timestamp.getSignerId());
		for (CertificateToken candidate : candidates) {
			if (timestamp.isSignedBy(candidate)) {
				return candidate;
			}
		}

		LOG.warn("TSA certificate not found in the certificate pool");

		return null;
	}

	/**
	 * Get the issuer's certificate from Authority Information Access through
	 * id-ad-caIssuers extension.
	 *
	 * @param token
	 *              {@code CertificateToken} for which the issuer is sought.
	 * @return {@code CertificateToken} representing the issuer certificate or null.
	 */
	private CertificateToken getIssuerFromAIA(final CertificateToken token) {
		LOG.info("Retrieving {} certificate's issuer using AIA.", token.getAbbreviation());
		Collection<CertificateToken> candidates = DSSUtils.loadPotentialIssuerCertificates(token, dataLoader);
		if (Utils.isCollectionNotEmpty(candidates)) {
			// The potential issuers might support 3 known scenarios:
			// - issuer certificate with single entry
			// - issuer certificate is a collection of bridge certificates (all having the
			// same public key)
			// - full certification path (up to the root of the chain)
			// In case the issuer is a collection of bridge certificates, only one of the
			// bridge certificates needs to be verified
			CertificateToken bridgedIssuer = findBestBridgeCertificate(token, candidates);
			if (bridgedIssuer != null) {
				addCertificateTokenForVerification(validationCertificatePool.getInstance(bridgedIssuer, CertificateSourceType.AIA));
				return bridgedIssuer;
			}
			for (CertificateToken candidate : candidates) {
				addCertificateTokenForVerification(validationCertificatePool.getInstance(candidate, CertificateSourceType.AIA));
			}
			for (CertificateToken candidate : candidates) {
				if (token.isSignedBy(candidate)) {
					if (!token.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
						LOG.info("There is AIA extension, but the issuer subject name and subject name does not match.");
						LOG.info("CERT ISSUER    : {}", token.getIssuerX500Principal());
						LOG.info("ISSUER SUBJECT : {}", candidate.getSubjectX500Principal());
					}
					return candidate;
				}
			}
			LOG.warn("The retrieved certificate(s) using AIA does not sign the certificate {}.", token.getAbbreviation());
		}
		return null;
	}

	private CertificateToken findBestBridgeCertificate(CertificateToken token, Collection<CertificateToken> candidates) {
		if (Utils.isCollectionEmpty(candidates) || candidates.size() == 1) {
			return null;
		}
		PublicKey commonPublicKey = null;
		CertificateToken bestMatch = null;
		for (CertificateToken candidate : candidates) {
			PublicKey candidatePublicKey = candidate.getPublicKey();
			if (commonPublicKey == null) {
				if (!token.isSignedBy(candidate)) {
					return null;
				}
				commonPublicKey = candidatePublicKey;
				bestMatch = candidate;
			} else if (!candidatePublicKey.equals(commonPublicKey)) {
				return null;
			} else if (isTrusted(bestMatch)) {
				continue;
			}

			List<CertificateToken> list = validationCertificatePool.get(candidate.getSubjectX500Principal());
			for (CertificateToken pooledToken : list) {
				if (pooledToken.getPublicKey().equals(commonPublicKey) && isTrusted(pooledToken)) {
					bestMatch = pooledToken;
					token.isSignedBy(pooledToken);
					break;
				}
			}
		}

		return bestMatch;
	}

	/**
	 * Adds a new token to the list of tokens to verify only if it was not already
	 * verified.
	 *
	 * @param token
	 *              token to verify
	 * @return true if the token was not yet verified, false otherwise.
	 */
	private boolean addTokenForVerification(final Token token) {
		if (token == null) {
			return false;
		}

		final boolean traceEnabled = LOG.isTraceEnabled();
		if (traceEnabled) {
			LOG.trace("addTokenForVerification: trying to acquire synchronized block");
		}

		synchronized (tokensToProcess) {
			try {
				if (tokensToProcess.containsKey(token)) {
					if (traceEnabled) {
						LOG.trace("Token was already in the list {}:{}", token.getClass().getSimpleName(), token.getAbbreviation());
					}
					return false;
				}

				tokensToProcess.put(token, null);
				if (traceEnabled) {
					LOG.trace("+ New {} to check: {}", token.getClass().getSimpleName(), token.getAbbreviation());
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
	public void addRevocationTokensForVerification(final List<RevocationToken> revocationTokens) {
		for (RevocationToken revocationToken : revocationTokens) {

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
	}

	@Override
	public void addCertificateTokenForVerification(final CertificateToken certificateToken) {

		if (addTokenForVerification(certificateToken)) {

			final boolean added = processedCertificates.add(certificateToken);
			if (LOG.isTraceEnabled()) {
				if (added) {
					LOG.trace("CertificateToken added to processedCertificates: {} ", certificateToken);
				} else {
					LOG.trace("CertificateToken already present processedCertificates: {} ", certificateToken);
				}
			}
		}
	}

	@Override
	public void addTimestampTokenForVerification(final TimestampToken timestampToken) {
		if (addTokenForVerification(timestampToken)) {

			registerUsageDate(timestampToken.getCreationDate(), timestampToken.getCertificates());

			final boolean added = processedTimestamps.add(timestampToken);
			if (LOG.isTraceEnabled()) {
				if (added) {
					LOG.trace("TimestampToken added to processedTimestamps: {} ", processedTimestamps);
				} else {
					LOG.trace("TimestampToken already present processedTimestamps: {} ", processedTimestamps);
				}
			}
		}
	}

	private void registerUsageDate(Date usageDate, List<CertificateToken> certificates) {
		for (CertificateToken cert : certificates) {
			Date lastUsage = lastUsageDates.get(cert);
			if (lastUsage == null || lastUsage.before(usageDate)) {
				lastUsageDates.put(cert, usageDate);
			}
		}
	}

	@Override
	public void validate() throws DSSException {
		Token token = getNotYetVerifiedToken();
		while (token != null) {

			List<Token> certChain = getCertChain(token);
			if (token instanceof CertificateToken) {
				final List<RevocationToken> revocationTokens = getRevocationData((CertificateToken) token, certChain);
				addRevocationTokensForVerification(revocationTokens);
			}
			token = getNotYetVerifiedToken();
		}
	}

	/**
	 * Retrieves the revocation data from signature (if exists) or from the online
	 * sources. The issuer certificate must be provided, the underlining library
	 * (bouncy castle) needs it to build the request.
	 *
	 * @param certToken
	 *                  the current token
	 * @param certChain
	 *                  the complete chain
	 * @return
	 */
	private List<RevocationToken> getRevocationData(final CertificateToken certToken, List<Token> certChain) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("Checking revocation data for : {}", certToken.getDSSIdAsString());
		}

		if (isRevocationDataNotRequired(certToken)) {
			return Collections.emptyList();
		}

		List<RevocationToken> revocations = new ArrayList<RevocationToken>();

		// ALL Embedded revocation data
		if (signatureCRLSource != null || signatureOCSPSource != null) {
			OCSPAndCRLCertificateVerifier offlineVerifier = new OCSPAndCRLCertificateVerifier(signatureCRLSource, signatureOCSPSource,
					validationCertificatePool);
			RevocationToken ocspToken = offlineVerifier.checkOCSP(certToken);
			if (ocspToken != null) {
				revocations.add(ocspToken);
			}

			RevocationToken crlToken = offlineVerifier.checkCRL(certToken);
			if (crlToken != null) {
				revocations.add(crlToken);
			}
		}
		

		if (revocations.isEmpty() || isRevocationDataRefreshNeeded(certToken, revocations)) {

			if (checkRevocationForUntrustedChains || isTrustedChain(certChain)) {

				// Online resources (OCSP and CRL if OCSP doesn't reply)
				OCSPAndCRLCertificateVerifier onlineVerifier = null;

				if (trustedCertSource instanceof CommonTrustedCertificateSource) {
					onlineVerifier = instantiateWithTrustServices((CommonTrustedCertificateSource) trustedCertSource, certToken, certChain);
				} else {
					onlineVerifier = new OCSPAndCRLCertificateVerifier(crlSource, ocspSource, validationCertificatePool);
				}

				final RevocationToken onlineRevocationToken = onlineVerifier.check(certToken);
				// CRL can already exist in the signature
				if (onlineRevocationToken != null && !revocations.contains(onlineRevocationToken)) {
					revocations.add(onlineRevocationToken);
				}
			} else {
				LOG.warn("External revocation check is skipped for untrusted certificate : {}", certChain.iterator().next().getDSSIdAsString());
			}
		}

		if (revocations.isEmpty()) {
			LOG.warn("No revocation found for certificate {}", certToken.getDSSIdAsString());
		}

		return revocations;
	}

	private boolean isTrustedChain(List<Token> certChain) {
		Token lastToken = certChain.get(certChain.size() - 1);
		return isTrusted(lastToken);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private OCSPAndCRLCertificateVerifier instantiateWithTrustServices(CommonTrustedCertificateSource trustedCertSource, CertificateToken certToken,
			List<Token> certChain) {

		CertificateToken trustAnchor = certToken;
		Token lastToken = certChain.get(certChain.size() - 1);
		if (lastToken instanceof CertificateToken) {
			trustAnchor = (CertificateToken) lastToken;
		}

		RevocationSource currentOCSPSource = null;
		List<String> alternativeOCSPUrls = trustedCertSource.getAlternativeOCSPUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeOCSPUrls) && ocspSource instanceof RevocationSourceAlternateUrlsSupport) {
			currentOCSPSource = new AlternateUrlsSourceAdapter<OCSPToken>((RevocationSourceAlternateUrlsSupport) ocspSource, alternativeOCSPUrls);
		} else {
			currentOCSPSource = ocspSource;
		}

		RevocationSource currentCRLSource = null;
		List<String> alternativeCRLUrls = trustedCertSource.getAlternativeCRLUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeCRLUrls) && crlSource instanceof RevocationSourceAlternateUrlsSupport) {
			currentCRLSource = new AlternateUrlsSourceAdapter<CRLToken>((RevocationSourceAlternateUrlsSupport) crlSource, alternativeCRLUrls);
		} else {
			currentCRLSource = crlSource;
		}

		return new OCSPAndCRLCertificateVerifier(currentCRLSource, currentOCSPSource, validationCertificatePool);
	}

	@Override
	public boolean isAllRequiredRevocationDataPresent() {
		for (CertificateToken certificateToken : processedCertificates) {
			if (!isRevocationDataNotRequired(certificateToken)) {
				boolean found = false;
				for (RevocationToken revocationToken : processedRevocations) {
					if (Utils.areStringsEqual(certificateToken.getDSSIdAsString(), revocationToken.getRelatedCertificateID())) {
						found = true;
						break;
					}
				}
				if (!found) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public boolean isAllTimestampValid() {
		for (TimestampToken timestampToken : processedTimestamps) {
			if (!timestampToken.isSignatureValid() || !timestampToken.isMessageImprintDataFound() || !timestampToken.isMessageImprintDataIntact()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean isAllCertificateValid() {
		for (CertificateToken certificateToken : processedCertificates) {
			if (!isRevocationDataNotRequired(certificateToken)) {
				for (RevocationToken revocationToken : processedRevocations) {
					if (Utils.areStringsEqual(certificateToken.getDSSIdAsString(), revocationToken.getRelatedCertificateID())
							&& !Utils.isTrue(revocationToken.getStatus())) {
						return false;
					}
				}
			}
		}
		return true;
	}

	private boolean isRevocationDataNotRequired(CertificateToken certToken) {
		return certToken.isSelfSigned() || isTrusted(certToken) || DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken);
	}

	private boolean isRevocationDataRefreshNeeded(CertificateToken certToken, List<RevocationToken> revocations) {
		Date lastUsageDate = lastUsageDates.get(certToken);
		if (lastUsageDate != null) {
			boolean foundUpdatedRevocationData = false;
			for (RevocationToken revocationToken : revocations) {
				if ((lastUsageDate.compareTo(revocationToken.getProductionDate()) <= 0) && (CRLReasonEnum.certificateHold != revocationToken.getReason())) {
					foundUpdatedRevocationData = true;
					break;
				}
			}

			if (!foundUpdatedRevocationData) {
				LOG.debug("Revocation data refresh is needed");
				return true;
			}
		}
		return false;
	}

	@Override
	public Set<CertificateToken> getProcessedCertificates() {
		return Collections.unmodifiableSet(processedCertificates);
	}

	@Override
	public Map<CertificateToken, Set<CertificateSourceType>> getCertificateSourceTypes() {
		Set<CertificateToken> certs = getProcessedCertificates();
		Map<CertificateToken, Set<CertificateSourceType>> result = new HashMap<CertificateToken, Set<CertificateSourceType>>();
		for (CertificateToken certificateToken : certs) {
			result.put(certificateToken, validationCertificatePool.getSources(certificateToken));
		}
		return result;
	}

	@Override
	public Set<RevocationToken> getProcessedRevocations() {
		return Collections.unmodifiableSet(processedRevocations);
	}

	@Override
	public Set<TimestampToken> getProcessedTimestamps() {
		return Collections.unmodifiableSet(processedTimestamps);
	}

	private boolean isTrusted(Token token) {
		return token instanceof CertificateToken && validationCertificatePool.isTrusted((CertificateToken) token);
	}

}
