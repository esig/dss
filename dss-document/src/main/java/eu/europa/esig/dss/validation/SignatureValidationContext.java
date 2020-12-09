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

import eu.europa.esig.dss.CertificateReorderer;
import eu.europa.esig.dss.alert.status.Status;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSourceAlternateUrlsSupport;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

/**
 * During the validation of a signature, the software retrieves different X509 artifacts like Certificate, CRL and OCSP
 * Response. The SignatureValidationContext is a "cache" for
 * one validation request that contains every object retrieved so far.
 *
 */
public class SignatureValidationContext implements ValidationContext {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureValidationContext.class);

	/**
	 * A set of certificates to process
	 */
	private final Set<CertificateToken> processedCertificates = new HashSet<>();

	/**
	 * A set of revocation data to process
	 */
	private final Set<RevocationToken<Revocation>> processedRevocations = new HashSet<>();

	/**
	 * A set of timestamps to process
	 */
	private final Set<TimestampToken> processedTimestamps = new HashSet<>();

	/**
	 * The CertificateVerifier to use
	 */
	private CertificateVerifier certificateVerifier;

	/**
	 * The data loader used to access AIA certificate source.
	 */
	private DataLoader dataLoader;

	/** Map of tokens defining if they have been processed yet */
	private final Map<Token, Boolean> tokensToProcess = new HashMap<>();

	/** The last usage of a timestamp's certificate tokens */
	private final Map<CertificateToken, Date> lastTimestampCertChainDates = new HashMap<>();

	/** A map of token IDs and their corresponding POE times */
	private final Map<String, List<Date>> poeTimes = new HashMap<>();
	
	/**
	 * The map contains all the certificate chains that has been used into the signature.
	 * Links the signing certificate and its chain.
	 * */
	private Map<CertificateToken, List<CertificateToken>> orderedCertificateChains;

	/** External OCSP source */
	private RevocationSource<OCSP> ocspSource;

	/** External CRL source */
	private RevocationSource<CRL> crlSource;

	/** External trusted certificate sources */
	private ListCertificateSource trustedCertSources;

	/** External adjunct certificate sources */
	private ListCertificateSource adjunctCertSources;

	/** CRLs from the signature */
	private ListRevocationSource<CRL> signatureCRLSource;

	/** OCSP from the signature */
	private ListRevocationSource<OCSP> signatureOCSPSource;

	/** Certificates from the signature */
	private ListCertificateSource signatureCertificateSource;
	
	/** Certificates collected from AIA */
	private ListCertificateSource aiaCertificateSources = new ListCertificateSource();

	/** Certificates collected from revocation tokens */
	private ListCertificateSource revocationCertificateSources = new ListCertificateSource();

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
	 * This constructor is used during the signature creation process.
	 */
	public SignatureValidationContext() {
	}

	/**
	 * @param certificateVerifier
	 *            The certificates verifier (eg: using the TSL as list of trusted certificates).
	 */
	@Override
	public void initialize(final CertificateVerifier certificateVerifier) {
		Objects.requireNonNull(certificateVerifier);

		this.certificateVerifier = certificateVerifier;
		this.crlSource = certificateVerifier.getCrlSource();
		this.ocspSource = certificateVerifier.getOcspSource();
		this.dataLoader = certificateVerifier.getDataLoader();
		this.signatureCRLSource = certificateVerifier.getSignatureCRLSource();
		this.signatureOCSPSource = certificateVerifier.getSignatureOCSPSource();
		this.signatureCertificateSource = certificateVerifier.getSignatureCertificateSource();
		this.adjunctCertSources = certificateVerifier.getAdjunctCertSources();
		this.trustedCertSources = certificateVerifier.getTrustedCertSources();
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
	 * This method returns a timestamp token to verify. If there is no more tokens to verify null is returned.
	 *
	 * @return token to verify or null
	 */
	private TimestampToken getNotYetVerifiedTimestamp() {
		synchronized (tokensToProcess) {
			for (final Entry<Token, Boolean> entry : tokensToProcess.entrySet()) {
				if (entry.getValue() == null && entry.getKey() instanceof TimestampToken) {
					entry.setValue(true);
					return (TimestampToken) entry.getKey();
				}
			}
			return null;
		}
	}
	
	private Map<CertificateToken, List<CertificateToken>> getOrderedCertificateChains() {
		if (orderedCertificateChains == null) {
			CertificateReorderer order = new CertificateReorderer(processedCertificates);
			orderedCertificateChains = order.getOrderedCertificateChains();
		}
		return orderedCertificateChains;
	}

	/**
	 * This method builds the complete certificate chain from the given token.
	 *
	 * @param token
	 *              the token for which the certificate chain must be obtained.
	 * @return the built certificate chain
	 */
	private List<Token> getCertChain(final Token token) {
		List<Token> chain = new LinkedList<>();
		Token issuerCertificateToken = token;
		do {
			chain.add(issuerCertificateToken);
			issuerCertificateToken = getIssuer(issuerCertificateToken);
		} while (issuerCertificateToken != null && !chain.contains(issuerCertificateToken));
		return chain;
	}

	private Token getIssuer(final Token token) {
		ListCertificateSource allCertificateSources = getAllCertificateSources();

		Set<CertificateToken> candidates = getIssuersFromSources(token, allCertificateSources);
		CertificateToken issuerCertificateToken = getTokenIssuerFromCandidates(token, candidates);

		if ((issuerCertificateToken == null) && (token instanceof CertificateToken) && dataLoader != null) {
			AIACertificateSource aiaSource = new AIACertificateSource((CertificateToken) token, dataLoader);
			aiaCertificateSources.add(aiaSource);
			issuerCertificateToken = aiaSource.getIssuerFromAIA();
		}
		
		if ((issuerCertificateToken == null) && (token instanceof OCSPToken)) {
			issuerCertificateToken = getOCSPIssuer((OCSPToken) token, allCertificateSources);
		}

		if ((issuerCertificateToken == null) && (token instanceof TimestampToken)) {
			issuerCertificateToken = getTSACertificate((TimestampToken) token, allCertificateSources);
		}

		if (issuerCertificateToken instanceof CertificateToken) {
			addCertificateTokenForVerification(issuerCertificateToken);
		}

		return issuerCertificateToken;
	}

	private ListCertificateSource getAllCertificateSources() {
		ListCertificateSource allCertificateSources = new ListCertificateSource();
		allCertificateSources.addAll(signatureCertificateSource);
		allCertificateSources.addAll(revocationCertificateSources);
		allCertificateSources.addAll(aiaCertificateSources);
		allCertificateSources.addAll(adjunctCertSources);
		allCertificateSources.addAll(trustedCertSources);
		return allCertificateSources;
	}

	private Set<CertificateToken> getIssuersFromSources(Token token, ListCertificateSource allCertificateSources) {
		if (token.getPublicKeyOfTheSigner() != null) {
			return allCertificateSources.getByPublicKey(token.getPublicKeyOfTheSigner());
		} else if (token.getIssuerX500Principal() != null) {
			return allCertificateSources.getBySubject(new X500PrincipalHelper(token.getIssuerX500Principal()));
		}
		return Collections.emptySet();
	}

	private CertificateToken getOCSPIssuer(OCSPToken token, ListCertificateSource allCertificateSources) {
		Set<CertificateRef> signingCertificateRefs = token.getCertificateSource().getAllCertificateRefs();
		if (Utils.collectionSize(signingCertificateRefs) == 1) {
			CertificateRef signingCertificateRef = signingCertificateRefs.iterator().next();
			ResponderId responderId = signingCertificateRef.getResponderId();
			if (responderId != null) {
				Set<CertificateToken> issuerCandidates = new HashSet<>();
				if (responderId.getSki() != null) {
					issuerCandidates.addAll(allCertificateSources.getBySki(responderId.getSki()));
				}
				if (responderId.getX500Principal() != null) {
					issuerCandidates.addAll(allCertificateSources.getBySubject(new X500PrincipalHelper(responderId.getX500Principal())));
				}
				return getTokenIssuerFromCandidates(token, issuerCandidates);
			}

		}
		LOG.warn("Signing certificate is not found for an OCSPToken with id '{}'.", token.getDSSIdAsString());
		return null;
	}

	private CertificateToken getTSACertificate(TimestampToken timestamp, ListCertificateSource allCertificateSources) {
		CandidatesForSigningCertificate candidatesForSigningCertificate = timestamp.getCandidatesForSigningCertificate();
		CertificateValidity theBestCandidate = candidatesForSigningCertificate.getTheBestCandidate();
		if (theBestCandidate != null) {
			Set<CertificateToken> issuerCandidates = new HashSet<>();
			CertificateToken timestampSigner = theBestCandidate.getCertificateToken();
			if (timestampSigner == null) {
				issuerCandidates.addAll(allCertificateSources.getByCertificateIdentifier(theBestCandidate.getSignerInfo()));
			} else {
				issuerCandidates.add(timestampSigner);
			}
			return getTokenIssuerFromCandidates(timestamp, issuerCandidates);
		}
		return null;
	}

	private CertificateToken getTokenIssuerFromCandidates(Token token, Collection<CertificateToken> candidates) {
		List<CertificateToken> issuers = new ArrayList<>();
		for (CertificateToken candidate : candidates) {
			if (token.isSignedBy(candidate)) {
				issuers.add(candidate);
				if (candidate.isValidOn(token.getCreationDate())) {
					return candidate;
				}
			}
		}
		if (Utils.isCollectionNotEmpty(issuers)) {
			LOG.warn("No issuer found for the token creation date. The process continues with an issuer which has the same public key.");
			return issuers.iterator().next();
		}
		return null;
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
				registerPOE(token.getDSSIdAsString(), currentTime);
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
	public void addRevocationTokenForVerification(RevocationToken<Revocation> revocationToken) {
		if (addTokenForVerification(revocationToken)) {

			// only certificate sources for OCSP tokens must be processed
			RevocationCertificateSource revocationCertificateSource = revocationToken.getCertificateSource();
			if (revocationCertificateSource != null) {
				revocationCertificateSources.add(revocationCertificateSource);
				for (CertificateToken certificateToken : revocationCertificateSource.getCertificates()) {
					addCertificateTokenForVerification(certificateToken);
				}
			}

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

			// Inject all certificate chain (needed in case of missing AIA on the TSA with
			// intermediate CAs)
			for (CertificateToken certificateToken : timestampToken.getCertificates()) {
				addCertificateTokenForVerification(certificateToken);
			}

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

	private void registerUsageDate(TimestampToken timestampToken) {
		CertificateToken tsaCertificate = getTSACertificate(timestampToken, getAllCertificateSources());
		if (tsaCertificate == null) {
			LOG.warn("No Timestamp Certificate found. Chain is skipped.");
			return;
		}
		
		Map<CertificateToken, List<CertificateToken>> certificateChains = getOrderedCertificateChains();
		List<CertificateToken> tsaCertificateChain = certificateChains.get(tsaCertificate);
		if (tsaCertificateChain == null) {
			tsaCertificateChain = toCertificateTokenChain(getCertChain(tsaCertificate));
			certificateChains.put(tsaCertificate, tsaCertificateChain);
		}
		Date usageDate = timestampToken.getCreationDate();
		for (CertificateToken cert : tsaCertificateChain) {
			if (isSelfSignedOrTrusted(cert)) {
				break;
			}
			Date lastUsage = lastTimestampCertChainDates.get(cert);
			if (lastUsage == null || lastUsage.before(usageDate)) {
				lastTimestampCertChainDates.put(cert, usageDate);
			}
		}
		for (TimestampedReference timestampedReference : timestampToken.getTimestampedReferences()) {
			registerPOE(timestampedReference.getObjectId(), usageDate);
		}
	}

	private void registerPOE(String tokenId, Date poeTime) {
		List<Date> poeTimeList = poeTimes.get(tokenId);
		if (Utils.isCollectionEmpty(poeTimeList)) {
			poeTimeList = new ArrayList<>();
			poeTimes.put(tokenId, poeTimeList);
		}
		poeTimeList.add(poeTime);
	}
	
	private List<CertificateToken> toCertificateTokenChain(List<Token> tokens) {
		List<CertificateToken> chain = new LinkedList<>();
		for (Token token : tokens) {
			if (token instanceof CertificateToken) {
				chain.add((CertificateToken) token);
			}
		}
		return chain;
	}

	@Override
	public void validate() {
		TimestampToken timestampToken = getNotYetVerifiedTimestamp();
		while (timestampToken != null) {
			getCertChain(timestampToken);
			registerUsageDate(timestampToken);
			timestampToken = getNotYetVerifiedTimestamp();
		}
		
		Token token = getNotYetVerifiedToken();
		while (token != null) {
			// extract the certificate chain and add missing tokens for verification
			List<Token> certChain = getCertChain(token);
			if (token instanceof CertificateToken) {
				getRevocationData((CertificateToken) token, certChain);
			}
			token = getNotYetVerifiedToken();
		}
	}

	/**
	 * Retrieves the revocation data from signature (if exists) or from the online
	 * sources. The issuer certificate must be provided, the underlining library
	 * (bouncy castle) needs it to build the request.
	 *
	 * @param certToken the current token
	 * @param certChain the complete chain
	 * @return a list of found {@link RevocationToken}s
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	private List<RevocationToken> getRevocationData(final CertificateToken certToken, List<Token> certChain) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("Checking revocation data for : {}", certToken.getDSSIdAsString());
		}

		if (isRevocationDataNotRequired(certToken)) {
			LOG.debug("Revocation data is not required for certificate : {}", certToken.getDSSIdAsString());
			return Collections.emptyList();
		}

		CertificateToken issuerToken = (CertificateToken) getIssuer(certToken);
		if (issuerToken == null) {
			LOG.warn("Issuer not found for certificate {}", certToken.getDSSIdAsString());
			return Collections.emptyList();
		}

		List<RevocationToken> revocations = new ArrayList<>();

		// ALL Embedded revocation data
		if (signatureCRLSource != null) {
			List<RevocationToken<CRL>> revocationTokens = signatureCRLSource.getRevocationTokens(certToken, issuerToken);
			for (RevocationToken revocationToken : revocationTokens) {
				revocations.add(revocationToken);
				addRevocationTokenForVerification(revocationToken);
			}
		}

		if (signatureOCSPSource != null) {
			List<RevocationToken<OCSP>> revocationTokens = signatureOCSPSource.getRevocationTokens(certToken, issuerToken);
			for (RevocationToken revocationToken : revocationTokens) {
				revocations.add(revocationToken);
				addRevocationTokenForVerification(revocationToken);
			}
		}
		
		if (Utils.isCollectionEmpty(revocations) || isRevocationDataRefreshNeeded(certToken, revocations)) {
			LOG.debug("The signature does not contain relative revocation data.");
			if (checkRevocationForUntrustedChains || containsTrustAnchor(certChain)) {
				LOG.trace("Revocation update is in progress for certificate : {}", certToken.getDSSIdAsString());
				CertificateToken trustAnchor = (CertificateToken) getFirstTrustAnchor(certChain);

				// Online resources (OCSP and CRL if OCSP doesn't reply)
				OCSPAndCRLRevocationSource onlineVerifier = null;
				if (!trustedCertSources.isEmpty() && (trustAnchor != null)) {
					LOG.trace("Initializing a revocation verifier for a trusted chain...");
					onlineVerifier = instantiateWithTrustServices(trustAnchor);
				} else {
					LOG.trace("Initializing a revocation verifier for not trusted chain...");
					onlineVerifier = new OCSPAndCRLRevocationSource(crlSource, ocspSource);
				}

				final RevocationToken<Revocation> onlineRevocationToken = onlineVerifier.getRevocationToken(certToken, issuerToken);
				// CRL can already exist in the signature
				if (onlineRevocationToken != null && !revocations.contains(onlineRevocationToken)) {
					LOG.debug("Obtained a new revocation data : {}, for certificate : {}", onlineRevocationToken.getDSSIdAsString(), certToken.getDSSIdAsString());
					revocations.add(onlineRevocationToken);
					addRevocationTokenForVerification(onlineRevocationToken);
				}
				
			} else {
				LOG.warn("External revocation check is skipped for untrusted certificate : {}", certToken.getDSSIdAsString());
			}
		}
		
		if (revocations.isEmpty()) {
			LOG.warn("No revocation found for the certificate {}", certToken.getDSSIdAsString());
		}

		return revocations;
	}

	private boolean containsTrustAnchor(List<Token> certChain) {
		return getFirstTrustAnchor(certChain) != null;
	}

	private Token getFirstTrustAnchor(List<Token> certChain) {
		for (Token token : certChain) {
			if (isTrusted(token)) {
				return token;
			}
		}
		return null;
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	private OCSPAndCRLRevocationSource instantiateWithTrustServices(CertificateToken trustAnchor) {
		RevocationSource currentOCSPSource = null;
		List<String> alternativeOCSPUrls = getAlternativeOCSPUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeOCSPUrls) && ocspSource instanceof RevocationSourceAlternateUrlsSupport) {
			currentOCSPSource = new AlternateUrlsSourceAdapter<OCSP>((RevocationSourceAlternateUrlsSupport) ocspSource, alternativeOCSPUrls);
		} else {
			currentOCSPSource = ocspSource;
		}

		RevocationSource currentCRLSource = null;
		List<String> alternativeCRLUrls = getAlternativeCRLUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeCRLUrls) && crlSource instanceof RevocationSourceAlternateUrlsSupport) {
			currentCRLSource = new AlternateUrlsSourceAdapter<CRL>((RevocationSourceAlternateUrlsSupport) crlSource, alternativeCRLUrls);
		} else {
			currentCRLSource = crlSource;
		}

		OCSPAndCRLRevocationSource ocspAndCrlRevocationSource = new OCSPAndCRLRevocationSource(currentCRLSource, currentOCSPSource);
		ocspAndCrlRevocationSource.setTrustedCertificateSource(trustedCertSources);
		return ocspAndCrlRevocationSource;
	}

	private List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor) {
		List<String> alternativeOCSPUrls = new ArrayList<>();
		for (CertificateSource certificateSource : trustedCertSources.getSources()) {
			if (certificateSource instanceof CommonTrustedCertificateSource) {
				CommonTrustedCertificateSource trustedCertSource = (CommonTrustedCertificateSource) certificateSource;
				alternativeOCSPUrls.addAll(trustedCertSource.getAlternativeOCSPUrls(trustAnchor));
			}
		}
		return alternativeOCSPUrls;
	}

	private List<String> getAlternativeCRLUrls(CertificateToken trustAnchor) {
		List<String> alternativeCRLUrls = new ArrayList<>();
		for (CertificateSource certificateSource : trustedCertSources.getSources()) {
			if (certificateSource instanceof CommonTrustedCertificateSource) {
				CommonTrustedCertificateSource trustedCertSource = (CommonTrustedCertificateSource) certificateSource;
				alternativeCRLUrls.addAll(trustedCertSource.getAlternativeCRLUrls(trustAnchor));
			}
		}
		return alternativeCRLUrls;
	}

	@Override
	public boolean checkAllRequiredRevocationDataPresent() {
		List<String> errors = new ArrayList<>();
		Map<CertificateToken, List<CertificateToken>> orderedCertificateChains = getOrderedCertificateChains();
		for (List<CertificateToken> orderedCertChain : orderedCertificateChains.values()) {
			checkRevocationForCertificateChainAgainstBestSignatureTime(orderedCertChain, null, errors);
		}
		if (!errors.isEmpty()) {
			Status status = new Status("Revocation data is missing for one or more certificate(s).", errors);
			certificateVerifier.getAlertOnMissingRevocationData().alert(status);
		}
		return errors.isEmpty();
	}
	
	private void checkRevocationForCertificateChainAgainstBestSignatureTime(List<CertificateToken> certificates, Date bestSignatureTime, List<String> errors) {
		for (CertificateToken certificateToken : certificates) {
			if (isSelfSignedOrTrusted(certificateToken)) {
				// break on the first trusted entry
				break;
			} else if (isOCSPNoCheckExtension(certificateToken)) {
				// skip the revocation check for OCSP certs if no check is specified
				continue;
			}
			
			boolean found = false;
			Date earliestNextUpdate = null; // used for informational purpose only
			for (RevocationToken<Revocation> revocationToken : processedRevocations) {
				
				if (Utils.areStringsEqual(certificateToken.getDSSIdAsString(), revocationToken.getRelatedCertificateID())) {
					if (bestSignatureTime == null || revocationToken.getThisUpdate().after(bestSignatureTime)) {
						found = true;
						break;
						
					} else {
						if (revocationToken.getNextUpdate() != null && 
								(earliestNextUpdate == null || revocationToken.getNextUpdate().before(earliestNextUpdate))) {
							earliestNextUpdate = revocationToken.getNextUpdate();
						}
						
					}
				}
			}
			
			if (!found) {
				if (bestSignatureTime == null) {
					// simple revocation presence check
					errors.add(String.format("No revocation data found for certificate : %s", certificateToken.getDSSIdAsString()));
				} else if (earliestNextUpdate != null) {
					errors.add(String.format(
							"No revocation data found after the best signature time [%s] "
							+ "for the certificate : %s. \n The nextUpdate available after : [%s]",
							bestSignatureTime, certificateToken.getDSSIdAsString(), earliestNextUpdate));
				} else {
					errors.add(String.format("No revocation data found after the best signature time [%s] for the certificate : %s", bestSignatureTime,
							certificateToken.getDSSIdAsString()));
				}
			}
		}
	}

	@Override
	public boolean checkAllPOECoveredByRevocationData() {
		List<String> errors = new ArrayList<>();
		for (Entry<CertificateToken, Date> entry : lastTimestampCertChainDates.entrySet()) {
			Date lastUsage = entry.getValue();
			CertificateToken token = entry.getKey();
			if (!isRevocationDataNotRequired(token)) {
				boolean foundValidRevocationDataAfterLastUsage = false;
				Date nextUpdate = null;
				for (RevocationToken<Revocation> revocationToken : processedRevocations) {
					if (Utils.areStringsEqual(token.getDSSIdAsString(), revocationToken.getRelatedCertificateID())) {
						Date productionDate = revocationToken.getProductionDate();
						if (productionDate.after(lastUsage)) {
							foundValidRevocationDataAfterLastUsage = true;
							break;
						}

						Date currentNextUpdate = revocationToken.getNextUpdate();
						if (nextUpdate == null || (currentNextUpdate != null && nextUpdate.before(currentNextUpdate))) {
							nextUpdate = currentNextUpdate;
						}
					}
				}
				if (!foundValidRevocationDataAfterLastUsage) {
					errors.add(String.format("POE '%s' not covered by a valid revocation data (nextUpdate : %s)", token.getDSSIdAsString(), nextUpdate));
				}
			}
		}
		if (!errors.isEmpty()) {
			Status status = new Status("Revocation data is missing for one or more POE(s).", errors);
			certificateVerifier.getAlertOnUncoveredPOE().alert(status);
		}
		return errors.isEmpty();
	}

	@Override
	public boolean checkAllTimestampsValid() {
		Set<String> invalidTimestampIds = new HashSet<>();
		for (TimestampToken timestampToken : processedTimestamps) {
			if (!timestampToken.isSignatureValid() || !timestampToken.isMessageImprintDataFound() || !timestampToken.isMessageImprintDataIntact()) {
				invalidTimestampIds.add(timestampToken.getDSSIdAsString());
			}
		}
		if (!invalidTimestampIds.isEmpty()) {
			Status status = new Status("Broken timestamp(s) detected.", invalidTimestampIds);
			certificateVerifier.getAlertOnInvalidTimestamp().alert(status);
		}
		return invalidTimestampIds.isEmpty();
	}

	@Override
	public boolean checkAllCertificatesValid() {
		Set<String> invalidCertificateIds = new HashSet<>();
		for (CertificateToken certificateToken : processedCertificates) {
			if (!isRevocationDataNotRequired(certificateToken)) {
				for (RevocationToken<Revocation> revocationToken : processedRevocations) {
					if (Utils.areStringsEqual(certificateToken.getDSSIdAsString(), revocationToken.getRelatedCertificateID())
							&& !revocationToken.getStatus().isGood()) {
						invalidCertificateIds.add(certificateToken.getDSSIdAsString());
					}
				}
			}
		}
		if (!invalidCertificateIds.isEmpty()) {
			Status status = new Status("Revoked/Suspended certificate(s) detected.", invalidCertificateIds);
			certificateVerifier.getAlertOnRevokedCertificate().alert(status);
		}
		return invalidCertificateIds.isEmpty();
	}

	private boolean isRevocationDataNotRequired(CertificateToken certToken) {
		return isSelfSignedOrTrusted(certToken) || isOCSPNoCheckExtension(certToken);
	}
	
	private boolean isSelfSignedOrTrusted(CertificateToken certToken) {
		return certToken.isSelfSigned() || isTrusted(certToken);
	}
	
	private boolean isOCSPNoCheckExtension(CertificateToken certToken) {
		return DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private boolean isRevocationDataRefreshNeeded(CertificateToken certToken, List<RevocationToken> revocations) {
		// get last usage dates for the same timestamp certificate chain
		Date refreshNeededAfterTime = lastTimestampCertChainDates.get(certToken);
		if (refreshNeededAfterTime == null) {
			// the best signature time for other tokens (i.e. B-level and revocation data)
			// shall not return null
			refreshNeededAfterTime = getLowestPOETime(certToken.getDSSIdAsString());
		}
		boolean freshRevocationDataFound = false;
		for (RevocationToken<Revocation> revocationToken : revocations) {
			if (refreshNeededAfterTime != null && (refreshNeededAfterTime.before(revocationToken.getProductionDate()))
					&& (RevocationReason.CERTIFICATE_HOLD != revocationToken.getReason()
					&& isConsistent(revocationToken))) {
				freshRevocationDataFound = true;
				break;
			}
		}
		if (!freshRevocationDataFound) {
			LOG.debug("Revocation data refresh is needed");
			return true;
		}
		return false;
	}
	
	private Date getLowestPOETime(String tokenId) {
		Date lowestPOE = null;
		List<Date> bestSignatureTimeList = poeTimes.get(tokenId);
		if (Utils.isCollectionNotEmpty(bestSignatureTimeList)) {
			for (Date poeTime : bestSignatureTimeList) {
				if (lowestPOE == null || poeTime.before(lowestPOE)) {
					lowestPOE = poeTime;
				}
			}
		}
		return lowestPOE;
	}
	
	private boolean isConsistent(RevocationToken<Revocation> revocation) {
		List<CertificateToken> certificateTokenChain = toCertificateTokenChain(getCertChain(revocation));
		if (Utils.isCollectionEmpty(certificateTokenChain)) {
			LOG.debug("The revocation {} is not consistent! Issuer CertificateToken is not found.", revocation.getDSSIdAsString());
			return false;
		}
		
		if (revocation.getNextUpdate() != null) {
			return hasPOEAfterProductionAndBeforeNextUpdate(revocation);
		} else {
			// if the next update time is not defined, check the validity of the issuer's certificate
			// useful for short-life certificates (i.e. ocsp responser)
			return hasPOEInTheValidityRange(certificateTokenChain.iterator().next());
		}
	}
	
	private boolean hasPOEAfterProductionAndBeforeNextUpdate(RevocationToken<Revocation> revocation) {
		List<Date> poeTimeList = poeTimes.get(revocation.getDSSIdAsString());
		if (Utils.isCollectionNotEmpty(poeTimeList)) {
			for (Date poeTime : poeTimeList) {
				if (isConsistentOnTime(revocation, poeTime)) {
					return true;
				}
			}
		}
		return false;
	}
	
	private boolean hasPOEInTheValidityRange(CertificateToken certificateToken) {
		List<Date> poeTimeList = poeTimes.get(certificateToken.getDSSIdAsString());
		if (Utils.isCollectionNotEmpty(poeTimeList)) {
			for (Date poeTime : poeTimeList) {
				if (certificateToken.isValidOn(poeTime)) {
					return true;
				}
				// continue
			}
		}
		return false;
	}
	
	private boolean isConsistentOnTime(RevocationToken<Revocation> revocationToken, Date date) {
		Date productionDate = revocationToken.getProductionDate();
		Date nextUpdate = revocationToken.getNextUpdate();
		return date.compareTo(productionDate) >= 0 && date.compareTo(nextUpdate) <= 0;
	}

	@Override
	public boolean checkAtLeastOneRevocationDataPresentAfterBestSignatureTime(CertificateToken signingCertificate) {
		List<String> errors = new ArrayList<>();
		Map<CertificateToken, List<CertificateToken>> orderedCertificateChains = getOrderedCertificateChains();
		for (Map.Entry<CertificateToken, List<CertificateToken>> entry : orderedCertificateChains.entrySet()) {
			CertificateToken firstChainCertificate = entry.getKey();
			Date bestSignatureTime = firstChainCertificate.equals(signingCertificate) ? getEarliestTimestampTime()
					: lastTimestampCertChainDates.get(firstChainCertificate);
			checkRevocationForCertificateChainAgainstBestSignatureTime(entry.getValue(), bestSignatureTime, errors);
		}
		if (!errors.isEmpty()) {
			Status status = new Status("Fresh revocation data is missing for one or more certificate(s).", errors);
			certificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime().alert(status);
		}
		return errors.isEmpty();
	}
	
	private Date getEarliestTimestampTime() {
		Date earliestDate = null;
		for (TimestampToken timestamp : getProcessedTimestamps()) {
			if (timestamp.getTimeStampType().coversSignature()) {
				Date timestampTime = timestamp.getCreationDate();
				if (earliestDate == null || timestampTime.before(earliestDate)) {
					earliestDate = timestampTime;
				}
			}
		}
		return earliestDate;
	}

	@Override
	public Set<CertificateToken> getProcessedCertificates() {
		return Collections.unmodifiableSet(processedCertificates);
	}

	@Override
	public Map<CertificateToken, Set<CertificateSourceType>> getCertificateSourceTypes() {
		ListCertificateSource allCertificateSources = getAllCertificateSources();
		Map<CertificateToken, Set<CertificateSourceType>> result = new HashMap<>();
		for (CertificateToken certificateToken : getProcessedCertificates()) {
			result.put(certificateToken, allCertificateSources.getCertificateSource(certificateToken));
		}
		return result;
	}

	@Override
	public Set<RevocationToken<Revocation>> getProcessedRevocations() {
		return Collections.unmodifiableSet(processedRevocations);
	}

	@Override
	public Set<TimestampToken> getProcessedTimestamps() {
		return Collections.unmodifiableSet(processedTimestamps);
	}

	private boolean isTrusted(Token token) {
		return token instanceof CertificateToken && trustedCertSources.isTrusted((CertificateToken) token);
	}

}
