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
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
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
import java.util.Arrays;
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
	 * Used to access certificate by AIA.
	 */
	private AIASource aiaSource;

	/** Map of tokens defining if they have been processed yet */
	private final Map<Token, Boolean> tokensToProcess = new HashMap<>();

	/** The last usage of a timestamp's certificate tokens */
	private final Map<CertificateToken, Date> lastTimestampCertChainDates = new HashMap<>();

	/** A map of token IDs and their corresponding POE times */
	private final Map<String, List<POE>> poeTimes = new HashMap<>();

	/** Cached map of tokens and their {@code CertificateToken} issuers */
	private final Map<Token, CertificateToken> tokenIssuerMap = new HashMap<>();
	
	/**
	 * The map contains all the certificate chains that has been used into the signature.
	 * Links the signing certificate and its chain.
	 * */
	private Map<CertificateToken, List<CertificateToken>> orderedCertificateChains;

	/** External OCSP source */
	private RevocationSource<OCSP> remoteOCSPSource;

	/** External CRL source */
	private RevocationSource<CRL> remoteCRLSource;

	/** This strategy defines the revocation loading logic and returns OCSP or CRL token for a provided certificate */
	private RevocationDataLoadingStrategy revocationDataLoadingStrategy;

	/** External trusted certificate sources */
	private ListCertificateSource trustedCertSources;

	/** External adjunct certificate sources */
	private ListCertificateSource adjunctCertSources;

	/** CRLs from the document */
	private ListRevocationSource<CRL> documentCRLSource = new ListRevocationSource<>();

	/** OCSP from the document */
	private ListRevocationSource<OCSP> documentOCSPSource = new ListRevocationSource<>();

	/** Certificates from the document */
	private ListCertificateSource documentCertificateSource = new ListCertificateSource();
	
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
		this.remoteCRLSource = certificateVerifier.getCrlSource();
		this.remoteOCSPSource = certificateVerifier.getOcspSource();
		this.aiaSource = certificateVerifier.getAIASource();
		this.revocationDataLoadingStrategy = certificateVerifier.getRevocationDataLoadingStrategy();
		this.adjunctCertSources = certificateVerifier.getAdjunctCertSources();
		this.trustedCertSources = certificateVerifier.getTrustedCertSources();
		this.checkRevocationForUntrustedChains = certificateVerifier.isCheckRevocationForUntrustedChains();
	}

	@Override
	public void addSignatureForVerification(final AdvancedSignature signature) {
		addDocumentCertificateSource(signature.getCertificateSource());
		addDocumentCRLSource(signature.getCRLSource());
		addDocumentOCSPSource(signature.getOCSPSource());

		// Add resolved certificates
		List<CertificateValidity> certificateValidities = signature.getCandidatesForSigningCertificate().getCertificateValidityList();
		if (Utils.isCollectionNotEmpty(certificateValidities)) {
			for (CertificateValidity certificateValidity : certificateValidities) {
				if (certificateValidity.isValid() && certificateValidity.getCertificateToken() != null) {
					addCertificateTokenForVerification(certificateValidity.getCertificateToken());
				}
			}
		}

		final List<CertificateToken> certificates = signature.getCertificates();
		for (final CertificateToken certificate : certificates) {
			addCertificateTokenForVerification(certificate);
		}
		prepareTimestamps(signature.getAllTimestamps());
		prepareCounterSignatures(signature.getCounterSignatures());
	}

	@Override
	public void addDocumentCertificateSource(CertificateSource certificateSource) {
		documentCertificateSource.add(certificateSource);
	}

	@Override
	public void addDocumentCertificateSource(ListCertificateSource certificateSource) {
		documentCertificateSource.addAll(certificateSource);
	}

	@Override
	public void addDocumentCRLSource(OfflineRevocationSource<CRL> crlSource) {
		documentCRLSource.add(crlSource);
	}

	@Override
	public void addDocumentCRLSource(ListRevocationSource<CRL> crlSource) {
		documentCRLSource.addAll(crlSource);
	}

	@Override
	public void addDocumentOCSPSource(OfflineRevocationSource<OCSP> ocspSource) {
		documentOCSPSource.add(ocspSource);
	}

	@Override
	public void addDocumentOCSPSource(ListRevocationSource<OCSP> ocspSource) {
		documentOCSPSource.addAll(ocspSource);
	}

	private void prepareTimestamps(final List<TimestampToken> timestampTokens) {
		for (final TimestampToken timestampToken : timestampTokens) {
			addTimestampTokenForVerification(timestampToken);
		}
	}

	private void prepareCounterSignatures(final List<AdvancedSignature> counterSignatures) {
		for (AdvancedSignature counterSignature : counterSignatures) {
			addSignatureForVerification(counterSignature);
		}
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

	private CertificateToken getIssuer(final Token token) {
		// Return cached value
		CertificateToken issuerCertificateToken = tokenIssuerMap.get(token);
		if (issuerCertificateToken != null) {
			return issuerCertificateToken;
		}

		// Find issuer from sources
		ListCertificateSource allCertificateSources = getAllCertificateSources();

		Set<CertificateToken> candidates = getIssuersFromSources(token, allCertificateSources);
		issuerCertificateToken = getTokenIssuerFromCandidates(token, candidates);

		if ((issuerCertificateToken == null) && (token instanceof CertificateToken) && aiaSource != null) {
			final AIACertificateSource aiaCertificateSource = new AIACertificateSource((CertificateToken) token, aiaSource);
			issuerCertificateToken = aiaCertificateSource.getIssuerFromAIA();
			aiaCertificateSources.add(aiaCertificateSource);
		}
		
		if ((issuerCertificateToken == null) && (token instanceof OCSPToken)) {
			issuerCertificateToken = getOCSPIssuer((OCSPToken) token, allCertificateSources);
		}

		if ((issuerCertificateToken == null) && (token instanceof TimestampToken)) {
			issuerCertificateToken = getTSACertificate((TimestampToken) token, allCertificateSources);
		}

		if (issuerCertificateToken != null) {
			addCertificateTokenForVerification(issuerCertificateToken);
			tokenIssuerMap.put(token, issuerCertificateToken);
		}

		return issuerCertificateToken;
	}

	private ListCertificateSource getAllCertificateSources() {
		ListCertificateSource allCertificateSources = new ListCertificateSource();
		allCertificateSources.addAll(documentCertificateSource);
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
			addDocumentCertificateSource(timestampToken.getCertificateSource());
			addDocumentCRLSource(timestampToken.getCRLSource());
			addDocumentOCSPSource(timestampToken.getOCSPSource());

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
			registerPOE(timestampedReference.getObjectId(), timestampToken);
		}
	}

	private void registerPOE(String tokenId, TimestampToken timestampToken) {
		List<POE> poeTimeList = poeTimes.get(tokenId);
		if (Utils.isCollectionEmpty(poeTimeList)) {
			poeTimeList = new ArrayList<>();
			poeTimes.put(tokenId, poeTimeList);
		}
		poeTimeList.add(new POE(timestampToken));
	}

	private void registerPOE(String tokenId, Date poeTime) {
		List<POE> poeTimeList = poeTimes.get(tokenId);
		if (Utils.isCollectionEmpty(poeTimeList)) {
			poeTimeList = new ArrayList<>();
			poeTimes.put(tokenId, poeTimeList);
		}
		poeTimeList.add(new POE(poeTime));
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

		CertificateToken issuerToken = getIssuer(certToken);
		if (issuerToken == null) {
			LOG.warn("Issuer not found for certificate {}", certToken.getDSSIdAsString());
			return Collections.emptyList();
		}

		List<RevocationToken> revocations = new ArrayList<>();

		// ALL Embedded revocation data
		if (documentCRLSource != null) {
			List<RevocationToken<CRL>> revocationTokens = documentCRLSource.getRevocationTokens(certToken, issuerToken);
			for (RevocationToken revocationToken : revocationTokens) {
				revocations.add(revocationToken);
				addRevocationTokenForVerification(revocationToken);
			}
		}

		if (documentOCSPSource != null) {
			List<RevocationToken<OCSP>> revocationTokens = documentOCSPSource.getRevocationTokens(certToken, issuerToken);
			for (RevocationToken revocationToken : revocationTokens) {
				revocations.add(revocationToken);
				addRevocationTokenForVerification(revocationToken);
			}
		}

		// add processed revocation tokens
		for (RevocationToken revocationToken : getRelatedRevocationTokens(certToken)) {
			revocations.add(revocationToken);
		}
		
		if (Utils.isCollectionEmpty(revocations) || isRevocationDataRefreshNeeded(certToken, revocations)) {
			LOG.debug("The signature does not contain relative revocation data.");
			if (checkRevocationForUntrustedChains || containsTrustAnchor(certChain)) {
				LOG.trace("Revocation update is in progress for certificate : {}", certToken.getDSSIdAsString());
				CertificateToken trustAnchor = (CertificateToken) getFirstTrustAnchor(certChain);

				// Fetch OCSP or CRL from online sources
				final RevocationToken<Revocation> onlineRevocationToken = getRevocationToken(
						certToken, issuerToken, trustAnchor);

				// Check if the obtained revocation is not yet present
				if (onlineRevocationToken != null && !revocations.contains(onlineRevocationToken)) {
					LOG.debug("Obtained a new revocation data : {}, for certificate : {}",
							onlineRevocationToken.getDSSIdAsString(), certToken.getDSSIdAsString());
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

	private <T extends Token> boolean containsTrustAnchor(List<T> certChain) {
		return getFirstTrustAnchor(certChain) != null;
	}

	private <T extends Token> Token getFirstTrustAnchor(List<T> certChain) {
		for (T token : certChain) {
			if (isTrusted(token)) {
				return token;
			}
		}
		return null;
	}

	private RevocationToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificate,
											   CertificateToken trustAnchor) {
		// configure the CompositeRevocationSource
		RevocationSource<OCSP> currentOCSPSource;
		RevocationSource<CRL> currentCRLSource;
		ListCertificateSource currentCertSource = null;
		if (!trustedCertSources.isEmpty() && (trustAnchor != null)) {
			LOG.trace("Initializing a revocation verifier for a trusted chain...");
			currentOCSPSource = instantiateOCSPWithTrustServices(trustAnchor);
			currentCRLSource = instantiateCRLWithTrustServices(trustAnchor);
			currentCertSource = trustedCertSources;
		} else {
			LOG.trace("Initializing a revocation verifier for not trusted chain...");
			currentOCSPSource = remoteOCSPSource;
			currentCRLSource = remoteCRLSource;
		}
		revocationDataLoadingStrategy.setOcspSource(currentOCSPSource);
		revocationDataLoadingStrategy.setCrlSource(currentCRLSource);
		revocationDataLoadingStrategy.setTrustedCertificateSource(currentCertSource);

		// fetch the data
		return revocationDataLoadingStrategy.getRevocationToken(certificateToken, issuerCertificate);
	}

	private RevocationSource<OCSP> instantiateOCSPWithTrustServices(CertificateToken trustAnchor) {
		List<String> alternativeOCSPUrls = getAlternativeOCSPUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeOCSPUrls) && remoteOCSPSource instanceof RevocationSourceAlternateUrlsSupport) {
			return new AlternateUrlsSourceAdapter<OCSP>((RevocationSourceAlternateUrlsSupport) remoteOCSPSource, alternativeOCSPUrls);
		} else {
			return remoteOCSPSource;
		}
	}

	private RevocationSource<CRL> instantiateCRLWithTrustServices(CertificateToken trustAnchor) {
		List<String> alternativeCRLUrls = getAlternativeCRLUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeCRLUrls) && remoteCRLSource instanceof RevocationSourceAlternateUrlsSupport) {
			return new AlternateUrlsSourceAdapter<CRL>((RevocationSourceAlternateUrlsSupport) remoteCRLSource, alternativeCRLUrls);
		} else {
			return remoteCRLSource;
		}
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
	
	private void checkRevocationForCertificateChainAgainstBestSignatureTime(List<CertificateToken> certificates,
			Date bestSignatureTime, List<String> errors) {
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

			List<RevocationToken> relatedRevocationTokens = getRelatedRevocationTokens(certificateToken);
			for (RevocationToken<Revocation> revocationToken : relatedRevocationTokens) {
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
			
			if (!found) {
				if (!certificateVerifier.isCheckRevocationForUntrustedChains() && !containsTrustAnchor(certificates)) {
					errors.add(String.format("Revocation data is skipped for untrusted certificate chain for the token : '%s'", certificateToken.getDSSIdAsString()));
				} else if (bestSignatureTime == null) {
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

			CertificateToken certificateToken = entry.getKey();
			if (!isRevocationDataNotRequired(certificateToken)) {

				boolean foundValidRevocationDataAfterLastUsage = false;
				Date nextUpdate = null;

				List<RevocationToken> relatedRevocationTokens = getRelatedRevocationTokens(certificateToken);
				for (RevocationToken<Revocation> revocationToken : relatedRevocationTokens) {
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
				if (!foundValidRevocationDataAfterLastUsage) {
					errors.add(String.format("POE '%s' not covered by a valid revocation data (nextUpdate : %s)",
							certificateToken.getDSSIdAsString(), nextUpdate));
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
			if (!timestampToken.isSignatureIntact() || !timestampToken.isMessageImprintDataFound() ||
					!timestampToken.isMessageImprintDataIntact()) {
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
				List<RevocationToken> relatedRevocationTokens = getRelatedRevocationTokens(certificateToken);
				// check only available revocation data in order to not duplicate
				// the method {@code checkAllRequiredRevocationDataPresent()}
				if (Utils.isCollectionNotEmpty(relatedRevocationTokens)) {
					// check if there is a best-signature-time before the revocation date
					Date lowestPOETime = getLowestPOETime(certificateToken);
					for (RevocationToken<Revocation> revocationToken : relatedRevocationTokens) {
						if ((revocationToken.getStatus().isRevoked() && lowestPOETime != null &&
								!lowestPOETime.before(revocationToken.getRevocationDate())) ||
								!revocationToken.getStatus().isKnown()) {
							invalidCertificateIds.add(certificateToken.getDSSIdAsString());
						}
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

	private List<RevocationToken> getRelatedRevocationTokens(CertificateToken certificateToken) {
		List<RevocationToken> result = new ArrayList<>();
		for (RevocationToken<Revocation> revocationToken : processedRevocations) {
			if (Utils.areStringsEqual(certificateToken.getDSSIdAsString(), revocationToken.getRelatedCertificateId())) {
				result.add(revocationToken);
			}
		}
		return result;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private boolean isRevocationDataRefreshNeeded(CertificateToken certToken, List<RevocationToken> revocations) {
		// get last usage dates for the same timestamp certificate chain
		Date refreshNeededAfterTime = lastTimestampCertChainDates.get(certToken);
		if (refreshNeededAfterTime == null) {
			// the best signature time for other tokens (i.e. B-level and revocation data)
			// shall not return null
			refreshNeededAfterTime = getLowestPOETime(certToken);
		}
		boolean freshRevocationDataFound = false;
		for (RevocationToken<Revocation> revocationToken : revocations) {
			if (refreshNeededAfterTime != null && (refreshNeededAfterTime.before(revocationToken.getProductionDate()))
					&& (RevocationReason.CERTIFICATE_HOLD != revocationToken.getReason()
					&& isConsistent(revocationToken, certToken))) {
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
	
	private Date getLowestPOETime(Token token) {
		Date lowestPOE = null;
		List<POE> poeList = poeTimes.get(token.getDSSIdAsString());
		if (Utils.isCollectionEmpty(poeList)) {
			throw new IllegalStateException("POE shall be defined before accessing the 'poeTimes' list!");
		}
		for (POE poe : poeList) {
			Date poeTime = poe.getTime();
			if (lowestPOE == null || poeTime.before(lowestPOE)) {
				lowestPOE = poeTime;
			}
		}
		return lowestPOE;
	}
	
	private boolean isConsistent(RevocationToken<Revocation> revocation, CertificateToken certToken) {
		List<CertificateToken> certificateTokenChain = toCertificateTokenChain(getCertChain(revocation));
		if (Utils.isCollectionEmpty(certificateTokenChain)) {
			LOG.debug("The revocation {} is not consistent! Issuer CertificateToken is not found.",
					revocation.getDSSIdAsString());
			return false;
		}

		if (RevocationType.OCSP.equals(revocation.getRevocationType()) &&
				!DSSRevocationUtils.checkIssuerValidAtRevocationProductionTime(revocation)) {
			LOG.debug("The revocation {} is not consistent! The revocation has been produced outside " +
					"the issuer certificate's validity range!", revocation.getDSSIdAsString());
			return false;
		}

		if (RevocationType.CRL.equals(revocation.getRevocationType()) && (
				!isInCertificateValidityRange(revocation, certToken))) {
			LOG.debug("The revocation '{}' was not issued during the validity period of the certificate! Certificate: {}",
					revocation.getDSSIdAsString(), certToken.getDSSIdAsString());
			return false;
		}
		
		if (revocation.getNextUpdate() != null) {
			return hasPOEAfterProductionAndBeforeNextUpdate(revocation);
		} else {
			// if the next update time is not defined, check the validity of the issuer's certificate
			// useful for short-life certificates (i.e. ocsp responder)
			return hasPOEInTheValidityRange(certificateTokenChain.iterator().next());
		}
	}

	private boolean isInCertificateValidityRange(RevocationToken<?> revocationToken, CertificateToken certificateToken) {
		final Date thisUpdate = revocationToken.getThisUpdate();
		final Date nextUpdate = revocationToken.getNextUpdate();
		final Date notAfter = certificateToken.getNotAfter();
		final Date notBefore = certificateToken.getNotBefore();
		return thisUpdate.compareTo(notAfter) <= 0 && (nextUpdate != null && nextUpdate.compareTo(notBefore) >= 0);
	}
	
	private boolean hasPOEAfterProductionAndBeforeNextUpdate(RevocationToken<Revocation> revocation) {
		List<POE> poeTimeList = poeTimes.get(revocation.getDSSIdAsString());
		if (Utils.isCollectionNotEmpty(poeTimeList)) {
			for (POE poeTime : poeTimeList) {
				if (isConsistentOnTime(revocation, poeTime.getTime())) {
					return true;
				}
			}
		}
		return false;
	}
	
	private boolean hasPOEInTheValidityRange(CertificateToken certificateToken) {
		List<POE> poeTimeList = poeTimes.get(certificateToken.getDSSIdAsString());
		if (Utils.isCollectionNotEmpty(poeTimeList)) {
			for (POE poeTime : poeTimeList) {
				if (certificateToken.isValidOn(poeTime.getTime())) {
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
	public boolean checkSignatureNotExpired(CertificateToken signingCertificate) {
		boolean signatureNotExpired = verifyCertificateTokenHasPOERecursively(signingCertificate);
		if (!signatureNotExpired) {
			Status status = new Status("The signing certificate has been expired and " +
					"there is no POE during its validity range.", Arrays.asList(signingCertificate.getDSSIdAsString()));
			certificateVerifier.getAlertOnExpiredSignature().alert(status);
		}
		return signatureNotExpired;
	}

	private boolean verifyCertificateTokenHasPOERecursively(CertificateToken certificateToken) {
		List<POE> poeTimeList = poeTimes.get(certificateToken.getDSSIdAsString());
		if (Utils.isCollectionNotEmpty(poeTimeList)) {
			for (POE poeTime : poeTimeList) {
				if (certificateToken.isValidOn(poeTime.getTime())) {
					TimestampToken timestampToken = poeTime.getTimestampToken();
					if (timestampToken != null) {
						// check if the timestamp is valid at validation time
						CertificateToken issuerCertificateToken = getIssuer(timestampToken);
						if (issuerCertificateToken != null &&
								verifyCertificateTokenHasPOERecursively(issuerCertificateToken)) {
							return true;
						}
					} else {
						// the certificate is valid at the current time
						return true;
					}
				}
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

	private <T extends Token> boolean isTrusted(T token) {
		return token instanceof CertificateToken && trustedCertSources.isTrusted((CertificateToken) token);
	}

	@Override
	public ValidationData getValidationData(final AdvancedSignature signature) {
		return getValidationData(signature.getSigningCertificateToken());
	}

	@Override
	public ValidationData getValidationData(final TimestampToken timestampToken) {
		return getValidationData(getIssuer(timestampToken));
	}

	private ValidationData getValidationData(final CertificateToken certificateToken) {
		ValidationData validationData = new ValidationData();
		if (certificateToken != null) {
			populateValidationDataRecursively(certificateToken, validationData);
		}
		return validationData;
	}

	private void populateValidationDataRecursively(final Token token, final ValidationData validationData) {
		boolean added = validationData.addToken(token);
		if (added) {
			if (token instanceof CertificateToken) {
				List<RevocationToken> revocationTokens = getRelatedRevocationTokens((CertificateToken) token);
				for (RevocationToken revocationToken : revocationTokens) {
					populateValidationDataRecursively(revocationToken, validationData);
				}
			}
			CertificateToken issuerToken = getIssuer(token);
			if (issuerToken != null) {
				populateValidationDataRecursively(issuerToken, validationData);
			}
		}
	}

	/**
	 * This class defines a POE provided to the validation process or obtained from processed timestamps
	 */
	private class POE {

		/** The POE time */
		private final Date time;

		/** The TimestampToken provided the POE, when present */
		private TimestampToken timestampToken;

		/**
		 * Default constructor to instantiate the object from a provided time
		 *
		 * @param time {@link Date}
		 */
		public POE(final Date time) {
			this.time = time;
		}

		/**
		 * Constructor to instantiate the POE object from a TimestampToken
		 *
		 * @param timestampToken {@link TimestampToken}
		 */
		public POE(TimestampToken timestampToken) {
			this.timestampToken = timestampToken;
			this.time = timestampToken.getCreationDate();
		}

		/**
		 * Returns the POE time
		 *
		 * @return {@link Date}
		 */
		public Date getTime() {
			return time;
		}

		/**
		 * Returns the TimestampToken used to create the POE, when present
		 *
		 * @return {@link TimestampToken} if it has been used for the POE, null otherwise
		 */
		public TimestampToken getTimestampToken() {
			return timestampToken;
		}

	}

}
