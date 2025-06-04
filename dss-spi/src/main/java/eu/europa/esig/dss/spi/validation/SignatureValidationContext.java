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

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.status.RevocationFreshnessStatus;
import eu.europa.esig.dss.spi.validation.status.SignatureStatus;
import eu.europa.esig.dss.spi.validation.status.TokenStatus;
import eu.europa.esig.dss.spi.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateReorderer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.TokenIssuerSelector;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIACertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSourceAlternateUrlsSupport;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampTokenComparator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
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
	 * A set of signatures to process
	 */
	private final Set<AdvancedSignature> processedSignatures = new LinkedHashSet<>();

	/**
	 * A set of certificates to process
	 */
	private final Set<CertificateToken> processedCertificates = new LinkedHashSet<>();

	/**
	 * A set of revocation data to process
	 */
	private final Set<RevocationToken<?>> processedRevocations = new LinkedHashSet<>();

	/**
	 * A set of timestamps to process
	 */
	private final Set<TimestampToken> processedTimestamps = new LinkedHashSet<>();

	/**
	 * A set of evidence records to process
	 */
	private final Set<EvidenceRecord> processedEvidenceRecords = new LinkedHashSet<>();

	/**
	 * The CertificateVerifier to use
	 */
	private CertificateVerifier certificateVerifier;

	/** Map of tokens defining if they have been processed yet */
	private final Map<Token, Boolean> tokensToProcess = new HashMap<>();

	/** A map between certificate tokens and corresponding signatures (b-level creation) */
	private final Map<CertificateToken, List<AdvancedSignature>> certificateSignaturesUsage = new HashMap<>();

	/** The usages of a timestamp's certificate tokens */
	private final Map<CertificateToken, List<Date>> timestampCertChainDates = new HashMap<>();

	/** A map of token IDs and their corresponding POE times */
	private final Map<String, List<POE>> poeTimes = new HashMap<>();

	/** Cached map of tokens and their {@code CertificateToken} issuers */
	private final Map<Token, CertificateToken> tokenIssuerMap = new HashMap<>();

	/** Cached map of parent {@code CertificateToken}'s and their corresponding issued certificates */
	private final Map<Token, Set<CertificateToken>> certificateChildrenMap = new HashMap<>();

	/** Certificates from the document */
	private final ListCertificateSource documentCertificateSource = new ListCertificateSource();

	/** CRLs from the document */
	private final ListRevocationSource<CRL> documentCRLSource = new ListRevocationSource<>();

	/** OCSP from the document */
	private final ListRevocationSource<OCSP> documentOCSPSource = new ListRevocationSource<>();

	/** Certificates collected from AIA */
	private final ListCertificateSource aiaCertificateSources = new ListCertificateSource();

	/** Certificates collected from revocation tokens */
	private final ListCertificateSource revocationCertificateSources = new ListCertificateSource();

	/** Used to access certificate by AIA */
	private AIASource aiaSource;

	/** External OCSP source */
	private RevocationSource<OCSP> remoteOCSPSource;

	/** External CRL source */
	private RevocationSource<CRL> remoteCRLSource;

	/** Used to build a strategy deciding how to retrieve a revocation data (e.g. CRL or OCSP) */
	private RevocationDataLoadingStrategyFactory revocationDataLoadingStrategyFactory;

	/** This class is used to verify the validity (i.e. consistency) of a revocation data */
	private RevocationDataVerifier revocationDataVerifier;

	/** Defines whether a revocation data still shall be returned, when validation of obtained revocation tokens failed */
	private boolean revocationFallback;

	/** This class is used to verify validity of a {@code TimestampToken} */
	private TimestampTokenVerifier timestampTokenVerifier;

	/** This class is used to verify whether a certificate is a trust anchor */
	private TrustAnchorVerifier trustAnchorVerifier;

	/** External trusted certificate sources */
	private ListCertificateSource trustedCertSources;

	/** External adjunct certificate sources */
	private ListCertificateSource adjunctCertSources;

	/**
	 * This variable set the behavior to follow for revocation retrieving in case of
	 * untrusted certificate chains.
	 */
	private boolean checkRevocationForUntrustedChains;

	/**
	 * This is the time at what the validation is carried out.
	 */
	protected Date currentTime;

	/**
	 * Default constructor instantiating object with null or empty values and current time
	 */
	public SignatureValidationContext() {
		this(new Date());
	}

	/**
	 * Constructor instantiating object with null or empty values and provided time
	 *
	 * @param validationTime {@link Date} validation time to be used during the execution
	 */
	public SignatureValidationContext(Date validationTime) {
		this.currentTime = validationTime;
	}

	/**
	 * @param certificateVerifier
	 *            The certificate verifier (eg: using the TSL as list of trusted certificates).
	 */
	@Override
	public void initialize(final CertificateVerifier certificateVerifier) {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null!");

		this.certificateVerifier = certificateVerifier;
		this.remoteCRLSource = certificateVerifier.getCrlSource();
		this.remoteOCSPSource = certificateVerifier.getOcspSource();
		this.aiaSource = certificateVerifier.getAIASource();
		this.adjunctCertSources = certificateVerifier.getAdjunctCertSources();
		this.trustedCertSources = certificateVerifier.getTrustedCertSources();
		this.checkRevocationForUntrustedChains = certificateVerifier.isCheckRevocationForUntrustedChains();
		this.revocationDataLoadingStrategyFactory = certificateVerifier.getRevocationDataLoadingStrategyFactory();
		this.revocationDataVerifier = certificateVerifier.getRevocationDataVerifier();
		this.revocationFallback = certificateVerifier.isRevocationFallback();
		this.timestampTokenVerifier = certificateVerifier.getTimestampTokenVerifier();
		this.trustAnchorVerifier = certificateVerifier.getTrustAnchorVerifier();
	}

	/**
	 * Gets the {@code CertificateVerifier} instance
	 *
	 * @return {@link CertificateVerifier}
	 */
	protected CertificateVerifier getCertificateVerifier() {
		Objects.requireNonNull(certificateVerifier,
				"CertificateVerifier shall be initialized! Please use #initialize(CertificateVerifier) method.");
		return certificateVerifier;
	}

	/**
	 * Returns an instance of {@code RevocationDataVerifier}.
	 * Instantiates a default configuration from a default validation policy, if not defined.
	 *
	 * @return {@link RevocationDataVerifier}
	 */
	private RevocationDataVerifier getRevocationDataVerifier() {
		if (revocationDataVerifier == null) {
			revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
		}
		if (revocationDataVerifier.getTrustAnchorVerifier() == null) {
			revocationDataVerifier.setTrustAnchorVerifier(getTrustAnchorVerifier());
		}
		revocationDataVerifier.setValidationContext(this);
		return revocationDataVerifier;
	}

	private TimestampTokenVerifier getTimestampTokenVerifier() {
		if (timestampTokenVerifier == null) {
			timestampTokenVerifier = TimestampTokenVerifier.createDefaultTimestampTokenVerifier();
		}
		if (timestampTokenVerifier.getTrustAnchorVerifier() == null) {
			timestampTokenVerifier.setTrustAnchorVerifier(getTrustAnchorVerifier());
		}
		if (timestampTokenVerifier.getRevocationDataVerifier() == null) {
			timestampTokenVerifier.setRevocationDataVerifier(getRevocationDataVerifier());
		}
		return timestampTokenVerifier;
	}

	private TrustAnchorVerifier getTrustAnchorVerifier() {
		if (trustAnchorVerifier == null) {
			trustAnchorVerifier = TrustAnchorVerifier.createDefaultTrustAnchorVerifier();
		}
		if (trustAnchorVerifier.getTrustedCertificateSource() == null) {
			trustAnchorVerifier.setTrustedCertificateSource(trustedCertSources);
		}
		return trustAnchorVerifier;
	}

	@Override
	public void addSignatureForVerification(final AdvancedSignature signature) {
		if (signature == null) {
			return;
		}

		addDocumentCertificateSource(signature.getCertificateSource());
		addDocumentCRLSource(signature.getCRLSource());
		addDocumentOCSPSource(signature.getOCSPSource());
		registerPOE(signature.getId(), currentTime);

		// Add resolved certificates
		CertificateToken signingCertificate = signature.getSigningCertificateToken();
		if (signingCertificate != null) {
			addCertificateTokenForVerification(signingCertificate);
		} else {
			List<CertificateValidity> certificateValidities = signature.getCandidatesForSigningCertificate().getCertificateValidityList();
			if (Utils.isCollectionNotEmpty(certificateValidities)) {
				for (CertificateValidity certificateValidity : certificateValidities) {
					if (certificateValidity.isValid() && certificateValidity.getCertificateToken() != null) {
						addCertificateTokenForVerification(certificateValidity.getCertificateToken());
					}
				}
			}
		}

		List<TimestampToken> timestamps = signature.getAllTimestamps();
		prepareTimestamps(timestamps);

		List<EvidenceRecord> allEvidenceRecords = signature.getAllEvidenceRecords();
		prepareEvidenceRecords(allEvidenceRecords);

		registerCertChainUsage(signature); // to be done after timestamp POE extraction

		final boolean added = processedSignatures.add(signature);
		if (LOG.isTraceEnabled()) {
			if (added) {
				LOG.trace("AdvancedSignature added to processedSignatures: {} ", processedSignatures);
			} else {
				LOG.trace("AdvancedSignature already present processedSignatures: {} ", processedSignatures);
			}
		}

		List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
		prepareCounterSignatures(counterSignatures);
	}

	@Override
	public void addDocumentCertificateSource(CertificateSource certificateSource) {
		addCertificateSource(documentCertificateSource, certificateSource);
	}

	@Override
	public void addDocumentCertificateSource(ListCertificateSource listCertificateSource) {
		for (CertificateSource certificateSource : listCertificateSource.getSources()) {
			addDocumentCertificateSource(certificateSource);
		}
	}

	/**
	 * Adds {@code certificateSourceToAdd} to the given {@code listCertificateSource}
	 *
	 * @param listCertificateSource {@link ListCertificateSource} to enrich
	 * @param certificateSourceToAdd {@link CertificateSource} to add
	 */
	private void addCertificateSource(ListCertificateSource listCertificateSource, CertificateSource certificateSourceToAdd) {
		if (listCertificateSource.add(certificateSourceToAdd)) {
			// add all existing equivalent certificates for the validation
			ListCertificateSource allCertificateSources = getAllCertificateSources();
			for (CertificateToken certificateToken : certificateSourceToAdd.getCertificates()) {
				addEquivalentCertificates(certificateToken, allCertificateSources);
			}
		}
	}

	private void addEquivalentCertificates(CertificateToken certificateToken, CertificateSource certificateSource) {
		final Set<CertificateToken> equivalentCertificates = certificateSource.getByEntityKey(certificateToken.getEntityKey());
		for (CertificateToken equivalentCertificate : equivalentCertificates) {
			if (!certificateToken.getDSSIdAsString().equals(equivalentCertificate.getDSSIdAsString())) {
				addCertificateTokenForVerification(equivalentCertificate);
			}
		}
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
		if (Utils.isCollectionNotEmpty(timestampTokens)) {
			for (final TimestampToken timestampToken : timestampTokens) {
				addTimestampTokenForVerification(timestampToken);
			}
		}
	}

	private void prepareEvidenceRecords(final List<EvidenceRecord> evidenceRecords) {
		if (Utils.isCollectionNotEmpty(evidenceRecords)) {
			for (EvidenceRecord evidenceRecord : evidenceRecords) {
				addEvidenceRecordForVerification(evidenceRecord);
			}
		}
	}

	private void registerCertChainUsage(AdvancedSignature signature) {
		CertificateToken signingCertificate = signature.getSigningCertificateToken();
		if (signingCertificate != null) {
			List<CertificateToken> certificateChain = toCertificateTokenChain(getCertChain(signingCertificate));
			for (CertificateToken cert : certificateChain) {
				List<AdvancedSignature> certUsageSignatures = certificateSignaturesUsage.computeIfAbsent(cert, k -> new ArrayList<>());
				if (!certUsageSignatures.contains(signature)) {
					certUsageSignatures.add(signature);
				}
			}
		}
	}

	private void prepareCounterSignatures(final List<AdvancedSignature> counterSignatures) {
		if (Utils.isCollectionNotEmpty(counterSignatures)) {
			for (AdvancedSignature counterSignature : counterSignatures) {
				addSignatureForVerification(counterSignature);
			}

		}
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	/**
	 * This method returns a token to verify. If there is no more tokens to verify null is returned.
	 *
	 * @return token to verify or null
	 */
	private Token getNotYetVerifiedToken() {
		synchronized (tokensToProcess) {
			RevocationToken<?> revocationToken = getNotYetVerifiedRevocationToken();
			if (revocationToken != null) {
				return revocationToken;
			}
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
	 * This method returns a revocation token to verify. If there is no more tokens to verify null is returned.
	 * As revocation tokens may be added dynamically, the method is executed as part of {@code getNotYetVerifiedToken}.
	 * It is called with a priority, in order to be able to identify a correct certificate chain.
	 *
	 * @return token to verify or null
	 */
	private RevocationToken<?> getNotYetVerifiedRevocationToken() {
		if (Utils.isCollectionEmpty(processedRevocations)) {
			return null;
		}
		final List<RevocationToken<?>> revocationTokens = new ArrayList<>(processedRevocations);
		for (RevocationToken<?> revocationToken : revocationTokens) {
			if (!isYetVerified(revocationToken)) {
				return revocationToken;
			}
		}
		return null;
	}

	/**
	 * This method returns a timestamp token to verify. If there is no more tokens to verify null is returned.
	 *
	 * @return token to verify or null
	 */
	private TimestampToken getNotYetVerifiedTimestamp() {
		if (Utils.isCollectionEmpty(processedTimestamps)) {
			return null;
		}
		final List<TimestampToken> sortedTimestampTokens = new ArrayList<>(processedTimestamps);
		sortedTimestampTokens.sort(new TimestampTokenComparator());
		Collections.reverse(sortedTimestampTokens); // start processing from the freshest timestamp
		for (TimestampToken timestampToken : sortedTimestampTokens) {
			if (!isYetVerified(timestampToken)) {
				return timestampToken;
			}
		}
		return null;
	}

	private Token getNotYetVerifiedTokenFromChain(List<Token> certChain) {
		for (Token token : certChain) {
			if (!isYetVerified(token)) {
				return token;
			}
		}
		return null;
	}

	private boolean isYetVerified(Token token) {
		synchronized (tokensToProcess) {
			Boolean processed = tokensToProcess.get(token);
			if (!Boolean.TRUE.equals(processed)) {
				tokensToProcess.put(token, true);
				return false;
			}
			return true;
		}
	}
	
	private Map<CertificateToken, List<CertificateToken>> getOrderedCertificateChains() {
		final CertificateReorderer order = new CertificateReorderer(processedCertificates);
		return order.getOrderedCertificateChains();
	}

	/**
	 * This method builds the complete certificate chain from the given token.
	 *
	 * @param token
	 *              the token for which the certificate chain must be obtained.
	 * @return the built certificate chain
	 */
	private List<Token> getCertChain(final Token token) {
		final List<Token> chain = new LinkedList<>();
		Token issuerCertificateToken = token;
		do {
			chain.add(issuerCertificateToken);
			issuerCertificateToken = getIssuer(issuerCertificateToken, getTokenCertificateSource(token));
		} while (issuerCertificateToken != null && !chain.contains(issuerCertificateToken));
		return chain;
	}

	private CertificateSource getTokenCertificateSource(final Token token) {
		if (token instanceof OCSPToken) {
			return ((OCSPToken) token).getCertificateSource();
		} else if (token instanceof TimestampToken) {
			return ((TimestampToken) token).getCertificateSource();
		}
		// other tokens do not have its own source
		return null;
	}

	/**
	 * This method computes certificate chain for the given {@code token} without including the current {@code token}
	 * to the chain, when it is not instance of {@code CertificateToken}
	 *
	 * @param token {@link Token}
	 * @return a list of {@link CertificateToken}s
	 */
	private List<CertificateToken> getCertificateTokenChain(final Token token) {
		final List<CertificateToken> certificateChain = new LinkedList<>();
		for (Token chainItem : getCertChain(token)) {
			if (chainItem instanceof CertificateToken) {
				certificateChain.add((CertificateToken) chainItem);
			}
		}
		return certificateChain;
	}

	private CertificateToken getIssuer(final Token token) {
		return getIssuer(token, null);
	}

	private CertificateToken getIssuer(final Token token, CertificateSource certificateSource) {
		// Return cached value
		CertificateToken issuerCertificateToken = getIssuerFromProcessedCertificates(token);
		if (issuerCertificateToken != null) {
			// ensure equivalent certificates are processed
			if (certificateSource != null) {
				addEquivalentCertificates(issuerCertificateToken, certificateSource);
			}

			return issuerCertificateToken;
		}

		// Find issuer candidates from a particular certificate source
		Set<CertificateToken> candidates = Collections.emptySet();

		// Avoid repeating over stateless sources
		if (!tokenIssuerMap.containsKey(token)) {

			if (certificateSource == null) {
				// OCSP or Timestamp
				certificateSource = getTokenCertificateSource(token);
			}

			if (certificateSource != null) {
				candidates = getIssuersFromSource(token, certificateSource);
			}

			// Find issuer candidates from document sources
			if (Utils.isCollectionEmpty(candidates)) {
				candidates = getIssuersFromSources(token, documentCertificateSource);
			}

		}

		// Find issuer candidates from all sources
		ListCertificateSource allCertificateSources = getAllCertificateSources();
		if (Utils.isCollectionEmpty(candidates)) {
			candidates = getIssuersFromSources(token, allCertificateSources);
		}

		// Find issuer from provided certificate tokens
		if (Utils.isCollectionEmpty(candidates)) {
			candidates = new HashSet<>();
			candidates.addAll(processedCertificates);
			candidates.addAll(documentCertificateSource.getCertificates());
		}

		candidates = ensureCandidatesFromProcessedCertificates(candidates);

		issuerCertificateToken = new TokenIssuerSelector(token, candidates).getIssuer();

		// Request AIA only when no issuer has been found yet
		if (issuerCertificateToken == null && aiaSource != null
				&& token instanceof CertificateToken && !tokenIssuerMap.containsKey(token)) {
			final AIACertificateSource aiaCertificateSource = new AIACertificateSource((CertificateToken) token, aiaSource);
			issuerCertificateToken = aiaCertificateSource.getIssuerFromAIA();
			addCertificateSource(aiaCertificateSources, aiaCertificateSource);
		}
		
		if (issuerCertificateToken == null && token instanceof OCSPToken) {
			issuerCertificateToken = getOCSPIssuer((OCSPToken) token, allCertificateSources);
		}

		if (issuerCertificateToken == null && token instanceof TimestampToken) {
			issuerCertificateToken = getTSACertificate((TimestampToken) token, allCertificateSources);
		}

		if (issuerCertificateToken != null) {
			addCertificateTokenForVerification(issuerCertificateToken);
		}

		// Cache the result (successful or unsuccessful)
		addToCacheMap(token, issuerCertificateToken);

		return issuerCertificateToken;
	}

	/**
	 * This method is used to ensure the processed certificates are used on validation, in order to avoid cases
	 * when another certificate is being updated (not provided to the validation)
	 *
	 * @param candidates a set of issuer candidate {@link CertificateToken}s
	 * @return a set of {@link CertificateToken}s
	 */
	private Set<CertificateToken> ensureCandidatesFromProcessedCertificates(Set<CertificateToken> candidates) {
		if (Utils.isCollectionEmpty(candidates)) {
			return Collections.emptySet();
		}
		final Set<CertificateToken> result = new HashSet<>();
		for (CertificateToken certificateToken : candidates) {
			for (CertificateToken processedCertificate : processedCertificates) {
				if (certificateToken.equals(processedCertificate)) {
					certificateToken = processedCertificate;
					break;
				}
			}
			result.add(certificateToken);
		}
		return result;
	}

	private void addToCacheMap(Token token, CertificateToken issuerCertificateToken) {
		tokenIssuerMap.put(token, issuerCertificateToken);

		if (token instanceof CertificateToken) {
			Set<CertificateToken> childrenCertificates = certificateChildrenMap.get(issuerCertificateToken);
			if (Utils.isCollectionEmpty(childrenCertificates)) {
				childrenCertificates = new HashSet<>();
				certificateChildrenMap.put(issuerCertificateToken, childrenCertificates);
			}
			childrenCertificates.add((CertificateToken) token);
		}
	}

	private CertificateToken getIssuerFromProcessedCertificates(Token token) {
		CertificateToken issuerCertificateToken = tokenIssuerMap.get(token);
		// isSignedBy(...) check is required when a certificate is present in different sources
		// in order to instantiate a public key of the signer
		if (issuerCertificateToken != null &&
				(token.getPublicKeyOfTheSigner() != null || token.isSignedBy(issuerCertificateToken))) {
			return issuerCertificateToken;
		}
		return null;
	}

	@Override
	public ListCertificateSource getAllCertificateSources() {
		ListCertificateSource allCertificateSources = new ListCertificateSource();
		allCertificateSources.addAll(documentCertificateSource);
		allCertificateSources.addAll(revocationCertificateSources);
		allCertificateSources.addAll(aiaCertificateSources);
		allCertificateSources.addAll(adjunctCertSources);
		allCertificateSources.addAll(trustedCertSources);
		return allCertificateSources;
	}

	@Override
	public ListCertificateSource getDocumentCertificateSource() {
		return documentCertificateSource;
	}

	@Override
	public ListRevocationSource<CRL> getDocumentCRLSource() {
		return documentCRLSource;
	}

	@Override
	public ListRevocationSource<OCSP> getDocumentOCSPSource() {
		return documentOCSPSource;
	}

	private Set<CertificateToken> getIssuersFromSources(Token token, ListCertificateSource allCertificateSources) {
		if (token.getIssuerEntityKey() != null) {
			EntityIdentifier entityKey = token.getIssuerEntityKey();
			return allCertificateSources.getByEntityKey(entityKey);
		} else if (token.getPublicKeyOfTheSigner() != null) {
			return allCertificateSources.getByPublicKey(token.getPublicKeyOfTheSigner());
		} else if (token.getIssuerX500Principal() != null) {
			return allCertificateSources.getBySubject(new X500PrincipalHelper(token.getIssuerX500Principal()));
		}
		return Collections.emptySet();
	}

	private Set<CertificateToken> getIssuersFromSource(Token token, CertificateSource certificateSource) {
		if (token.getIssuerEntityKey() != null) {
			EntityIdentifier entityKey = token.getIssuerEntityKey();
			return certificateSource.getByEntityKey(entityKey);
		} else if (token.getPublicKeyOfTheSigner() != null) {
			return certificateSource.getByPublicKey(token.getPublicKeyOfTheSigner());
		} else if (token.getIssuerX500Principal() != null) {
			return certificateSource.getBySubject(new X500PrincipalHelper(token.getIssuerX500Principal()));
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
				return new TokenIssuerSelector(token, issuerCandidates).getIssuer();
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
				issuerCandidates.addAll(allCertificateSources.getBySignerIdentifier(theBestCandidate.getSignerInfo()));
			} else {
				issuerCandidates.add(timestampSigner);
			}
			return new TokenIssuerSelector(timestamp, issuerCandidates).getIssuer();
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
	public void addRevocationTokenForVerification(RevocationToken<?> revocationToken) {
		if (addTokenForVerification(revocationToken)) {

			RevocationCertificateSource revocationCertificateSource = revocationToken.getCertificateSource();
			if (revocationCertificateSource != null) {
				addCertificateSource(revocationCertificateSources, revocationCertificateSource);
			}

			CertificateToken issuerCertificateToken = revocationToken.getIssuerCertificateToken();
			if (issuerCertificateToken != null) {
				addCertificateTokenForVerification(issuerCertificateToken);
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

			List<CertificateValidity> certificateValidities = timestampToken.getCandidatesForSigningCertificate().getCertificateValidityList();
			if (Utils.isCollectionNotEmpty(certificateValidities)) {
				for (CertificateValidity certificateValidity : certificateValidities) {
					if (certificateValidity.isValid() && certificateValidity.getCertificateToken() != null) {
						addCertificateTokenForVerification(certificateValidity.getCertificateToken());
					}
				}
			}

			registerTimestampUsageDate(timestampToken);

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

	private void registerTimestampUsageDate(TimestampToken timestampToken) {
		CertificateToken tsaCertificate = getTSACertificate(timestampToken, getAllCertificateSources());
		if (tsaCertificate == null) {
			LOG.warn("No Timestamp Certificate found. Chain is skipped.");
			return;
		}

		List<CertificateToken> tsaCertificateChain = toCertificateTokenChain(getCertChain(timestampToken));
		Date usageDate = timestampToken.getCreationDate();
		for (CertificateToken cert : tsaCertificateChain) {
			List<Date> timestampCertChainUsageTimes = timestampCertChainDates.computeIfAbsent(cert, k -> new ArrayList<>());
			if (!timestampCertChainUsageTimes.contains(usageDate)) {
				timestampCertChainUsageTimes.add(usageDate);
			}
		}
	}

	private void registerTimestampPOE(TimestampToken timestampToken) {
		if (isTimestampValid(timestampToken)) {
			LOG.debug("Extracting POE from timestamp : {}", timestampToken.getDSSIdAsString());
			for (TimestampedReference timestampedReference : timestampToken.getTimestampedReferences()) {
				registerPOE(timestampedReference.getObjectId(), timestampToken);
			}
		}
	}

	/**
	 * This method verifies whether a {@code timestampToken} is valid and
	 * can be used as a valid POE for covered objects
	 *
	 * @param timestampToken {@link TimestampToken} to be checked
	 * @return TRUE if the timestamp is valid, FALSE otherwise
	 */
	protected boolean isTimestampValid(TimestampToken timestampToken) {
		List<CertificateToken> certificateTokenChain = getCertificateTokenChain(timestampToken);
		Date lowestPOETime = getLowestPOETime(timestampToken);
		return getTimestampTokenVerifier().isAcceptable(timestampToken, certificateTokenChain, lowestPOETime);
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
	public void addEvidenceRecordForVerification(EvidenceRecord evidenceRecord) {
		addDocumentCertificateSource(evidenceRecord.getCertificateSource());
		addDocumentCRLSource(evidenceRecord.getCRLSource());
		addDocumentOCSPSource(evidenceRecord.getOCSPSource());
		prepareTimestamps(evidenceRecord.getTimestamps());

		final boolean added = processedEvidenceRecords.add(evidenceRecord);
		if (LOG.isTraceEnabled()) {
			if (added) {
				LOG.trace("EvidenceRecord added to processedEvidenceRecords: {} ", processedSignatures);
			} else {
				LOG.trace("EvidenceRecord already present processedEvidenceRecords: {} ", processedSignatures);
			}
		}
	}

	@Override
	public void validate() {
		TimestampToken timestampToken = getNotYetVerifiedTimestamp();
		while (timestampToken != null) {
			validateTimestamp(timestampToken);
			timestampToken = getNotYetVerifiedTimestamp();
		}
		
		Token token = getNotYetVerifiedToken();
		while (token != null) {
			validateToken(token);
			token = getNotYetVerifiedToken();
		}
	}

	private void validateTimestamp(TimestampToken timestampToken) {
		List<Token> certChain = getCertChain(timestampToken);
		Token token = getNotYetVerifiedTokenFromChain(certChain);
		while (token != null) {
			validateToken(token);
			token = getNotYetVerifiedTokenFromChain(certChain);
		}
		registerTimestampPOE(timestampToken); // POE is extracted after TST validation
	}

	private void validateToken(Token token) {
		// extract the certificate chain and add missing tokens for verification
		List<Token> certChain = getCertChain(token);
		if (Utils.collectionSize(certChain) > 1) { // ensure certificate chain is processed
			Token certChainToken = getNotYetVerifiedTokenFromChain(certChain);
			if (certChainToken != null) {
				validateToken(certChainToken);
			}
		}
		if (token instanceof CertificateToken) {
			findRevocationData((CertificateToken) token, certChain);
		}
	}

	private void validateTokenIfNeeded(Token token) {
		addTokenForVerification(token); // ensure the token is added to the validation context
		if (!isYetVerified(token)) {
			validateToken(token);
		}
	}

	/**
	 * Retrieves the revocation data from signature (if exists) or from the online
	 * sources. The issuer certificate must be provided, the underlining library
	 * (bouncy castle) needs it to build the request.
	 *
	 * @param certToken the current token
	 * @param certChain the complete chain
	 * @return a set of found {@link RevocationToken}s
	 */
	private Set<RevocationToken<?>> findRevocationData(final CertificateToken certToken, List<Token> certChain) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("Checking revocation data for : {}", certToken.getDSSIdAsString());
		}

		if (isRevocationDataNotRequired(certToken, getLowestPOETime(certToken))) {
			LOG.debug("Revocation data is not required for certificate : {}", certToken.getDSSIdAsString());
			return Collections.emptySet();
		}

		CertificateToken issuerToken = getIssuer(certToken);
		if (issuerToken == null) {
			LOG.warn("Issuer not found for certificate {}", certToken.getDSSIdAsString());
			return Collections.emptySet();
		}

		Set<RevocationToken<?>> revocations = new HashSet<>();

		// ALL Embedded revocation data
		List<RevocationToken<CRL>> crlTokens = documentCRLSource.getRevocationTokens(certToken, issuerToken);
		for (RevocationToken<CRL> revocationToken : crlTokens) {
			revocations.add(revocationToken);
			addRevocationTokenForVerification(revocationToken);
		}

		List<RevocationToken<OCSP>> ocspTokens = documentOCSPSource.getRevocationTokens(certToken, issuerToken);
		for (RevocationToken<OCSP> revocationToken : ocspTokens) {
			revocations.add(revocationToken);
			addRevocationTokenForVerification(revocationToken);
			addDocumentCertificateSource(revocationToken.getCertificateSource()); // applicable only for OCSP
		}

		// add processed revocation tokens
		revocations.addAll(getRelatedRevocationTokens(certToken));

		if ((remoteOCSPSource != null || remoteCRLSource != null) &&
				(Utils.isCollectionEmpty(revocations) || isRevocationDataRefreshNeeded(certToken, revocations))) {
			LOG.debug("The signature does not contain relative revocation data.");
			if (checkRevocationForUntrustedChains || containsTrustAnchor(certChain)) {
				LOG.trace("Revocation update is in progress for certificate : {}", certToken.getDSSIdAsString());
				CertificateToken trustAnchor = (CertificateToken) getFirstTrustAnchor(certChain);

				// Fetch OCSP or CRL from online sources
				final RevocationToken<?> onlineRevocationToken = getRevocationToken(certToken, issuerToken, trustAnchor);

				// Check if the obtained revocation is not yet present
				if (onlineRevocationToken != null && !revocations.contains(onlineRevocationToken)) {
					LOG.debug("Obtained a new revocation data : {}, for certificate : {}",
							onlineRevocationToken.getDSSIdAsString(), certToken.getDSSIdAsString());
					revocations.add(onlineRevocationToken);
					addRevocationTokenForVerification(onlineRevocationToken);
					linkRevocationToOtherCertificates(onlineRevocationToken, certToken, issuerToken);
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

	@Override
	public List<RevocationToken<?>> getRevocationData(CertificateToken certificateToken) {
		validateTokenIfNeeded(certificateToken);
		List<RevocationToken<?>> result = new ArrayList<>();
		for (RevocationToken<?> revocationToken : processedRevocations) {
			if (Utils.areStringsEqual(certificateToken.getDSSIdAsString(), revocationToken.getRelatedCertificateId())) {
				result.add(revocationToken);
			}
		}
		return result;
	}

	private <T extends Token> boolean containsTrustAnchor(List<T> certChain) {
		return getFirstTrustAnchor(certChain) != null;
	}

	private <T extends Token> Token getFirstTrustAnchor(List<T> certChain) {
		if (Utils.isCollectionNotEmpty(certChain)) {
			for (T token : certChain) {
				if (isTrustedAtUsageTime(token)) {
					return token;
				}
			}
		}
		return null;
	}

	private <T extends Token> boolean containsTrustAnchorAtTime(List<T> certChain, Date controlTime) {
		if (Utils.isCollectionNotEmpty(certChain)) {
			for (T token : certChain) {
				if (isTrustedAtTime(token, controlTime)) {
					return true;
				}
			}
		}
		return false;
	}

	private void linkRevocationToOtherCertificates(RevocationToken<?> revocationToken, CertificateToken certificateToken,
												   CertificateToken issuerCertificateToken) {
		// Only CRL may relate to multiple certificates
		if (revocationToken instanceof CRLToken) {
			CRLToken crlToken = (CRLToken) revocationToken;
			Set<CertificateToken> certificateTokens = certificateChildrenMap.get(issuerCertificateToken);
			for (CertificateToken childCertificate : certificateTokens) {
				if (certificateToken != childCertificate) {
					CRLToken newCRLToken = new CRLToken(childCertificate, crlToken.getCrlValidity());
					newCRLToken.setExternalOrigin(crlToken.getExternalOrigin());
					newCRLToken.setSourceURL(crlToken.getSourceURL());
					addRevocationTokenForVerification(newCRLToken);
				}
			}
		}
	}

	private RevocationToken<?> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificate,
												  CertificateToken trustAnchor) {
		// configure the CompositeRevocationSource
		RevocationSource<OCSP> currentOCSPSource;
		RevocationSource<CRL> currentCRLSource;
		if (!trustedCertSources.isEmpty() && trustAnchor != null) {
			LOG.trace("Initializing a revocation verifier for a trusted chain...");
			currentOCSPSource = instantiateOCSPWithTrustServices(trustAnchor);
			currentCRLSource = instantiateCRLWithTrustServices(trustAnchor);
		} else {
			LOG.trace("Initializing a revocation verifier for not trusted chain...");
			currentOCSPSource = remoteOCSPSource;
			currentCRLSource = remoteCRLSource;
		}

		// fetch the data
		final RevocationDataLoadingStrategy revocationDataLoadingStrategy = revocationDataLoadingStrategyFactory.create();
		revocationDataLoadingStrategy.setCrlSource(currentCRLSource);
		revocationDataLoadingStrategy.setOcspSource(currentOCSPSource);
		revocationDataLoadingStrategy.setRevocationDataVerifier(getRevocationDataVerifier());
		revocationDataLoadingStrategy.setFallbackEnabled(revocationFallback);
		return revocationDataLoadingStrategy.getRevocationToken(certificateToken, issuerCertificate);
	}

	private RevocationSource<OCSP> instantiateOCSPWithTrustServices(CertificateToken trustAnchor) {
		List<String> alternativeOCSPUrls = getAlternativeOCSPUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeOCSPUrls) && remoteOCSPSource instanceof RevocationSourceAlternateUrlsSupport) {
			return new AlternateUrlsSourceAdapter<>((RevocationSourceAlternateUrlsSupport<OCSP>) remoteOCSPSource, alternativeOCSPUrls);
		} else {
			return remoteOCSPSource;
		}
	}

	private RevocationSource<CRL> instantiateCRLWithTrustServices(CertificateToken trustAnchor) {
		List<String> alternativeCRLUrls = getAlternativeCRLUrls(trustAnchor);
		if (Utils.isCollectionNotEmpty(alternativeCRLUrls) && remoteCRLSource instanceof RevocationSourceAlternateUrlsSupport) {
			return new AlternateUrlsSourceAdapter<>((RevocationSourceAlternateUrlsSupport<CRL>) remoteCRLSource, alternativeCRLUrls);
		} else {
			return remoteCRLSource;
		}
	}

	private List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor) {
		List<String> alternativeOCSPUrls = new ArrayList<>();
		for (CertificateSource certificateSource : trustedCertSources.getSources()) {
			if (certificateSource instanceof TrustedCertificateSource) {
				TrustedCertificateSource trustedCertSource = (TrustedCertificateSource) certificateSource;
				alternativeOCSPUrls.addAll(trustedCertSource.getAlternativeOCSPUrls(trustAnchor));
			}
		}
		return alternativeOCSPUrls;
	}

	private List<String> getAlternativeCRLUrls(CertificateToken trustAnchor) {
		List<String> alternativeCRLUrls = new ArrayList<>();
		for (CertificateSource certificateSource : trustedCertSources.getSources()) {
			if (certificateSource instanceof TrustedCertificateSource) {
				TrustedCertificateSource trustedCertSource = (TrustedCertificateSource) certificateSource;
				alternativeCRLUrls.addAll(trustedCertSource.getAlternativeCRLUrls(trustAnchor));
			}
		}
		return alternativeCRLUrls;
	}

	@Override
	public boolean checkAllRequiredRevocationDataPresent() {
		return allRequiredRevocationDataPresent().isEmpty();
	}

	/**
	 * Returns the status of the required revocation data present check
	 *
	 * @return {@link TokenStatus}
	 */
	protected TokenStatus allRequiredRevocationDataPresent() {
		TokenStatus status = new TokenStatus();
		Map<CertificateToken, List<CertificateToken>> orderedCertificateChains = getOrderedCertificateChains();
		for (List<CertificateToken> orderedCertChain : orderedCertificateChains.values()) {
			checkRevocationForCertificateChainAgainstBestSignatureTime(orderedCertChain, null, status);
		}
		boolean success = status.isEmpty();
		if (!success) {
			status.setMessage("Revocation data is missing for one or more certificate(s).");
		}
		return status;
	}
	
	private void checkRevocationForCertificateChainAgainstBestSignatureTime(List<CertificateToken> certificates,
			Date bestSignatureTime, TokenStatus status) {
		for (CertificateToken certificateToken : certificates) {
			if (isSelfSignedOrTrustedAtTime(certificateToken, bestSignatureTime)) {
				// break on the first trusted entry
				break;
			} else if (isRevocationDataNotRequired(certificateToken, bestSignatureTime)) {
				// skip the revocation check for OCSP certs if no check is specified
				continue;
			}
			
			boolean found = false;
			Date earliestNextUpdate = null;

			List<RevocationToken<?>> relatedRevocationTokens = getRelatedRevocationTokens(certificateToken);
			for (RevocationToken<?> revocationToken : relatedRevocationTokens) {
				if (bestSignatureTime == null || bestSignatureTime.before(revocationToken.getThisUpdate())) {
					found = true;
					break;

				} else {
					if (revocationToken.getNextUpdate() != null &&
							(earliestNextUpdate == null || earliestNextUpdate.after(revocationToken.getNextUpdate())) &&
							currentTime.before(revocationToken.getNextUpdate())) {
						earliestNextUpdate = revocationToken.getNextUpdate();
					}
				}
			}
			
			if (!found) {
				if (!getCertificateVerifier().isCheckRevocationForUntrustedChains() && !containsTrustAnchorAtTime(certificates, bestSignatureTime)) {
					status.addRelatedTokenAndErrorMessage(certificateToken,
							"Revocation data is skipped for untrusted certificate chain!");

				} else if (Utils.isCollectionEmpty(relatedRevocationTokens) || bestSignatureTime == null) {
					// simple revocation presence check
					status.addRelatedTokenAndErrorMessage(certificateToken, "No revocation data found for certificate!");

				} else if (earliestNextUpdate != null) {
					status.addRelatedTokenAndErrorMessage(certificateToken, String.format(
							"No revocation data found after the best signature time [%s]! " +
									"The nextUpdate available after : [%s]",
							DSSUtils.formatDateToRFC(bestSignatureTime), DSSUtils.formatDateToRFC(earliestNextUpdate)));

				} else {
					status.addRelatedTokenAndErrorMessage(certificateToken, String.format(
							"No revocation data found after the best signature time [%s]!",
							DSSUtils.formatDateToRFC(bestSignatureTime)));
				}

				if (status instanceof RevocationFreshnessStatus) {
					if (Utils.isCollectionNotEmpty(relatedRevocationTokens) && noNextUpdateDefined(relatedRevocationTokens)
							&& earliestNextUpdate == null) {
						// Define next update based on Timestamp time, when no NextUpdate is defined
						Date lowestPOETime = getLowestPOETime(certificateToken);
						if (lowestPOETime != null) {
							earliestNextUpdate = new Date(lowestPOETime.getTime() + 1000); // last usage + 1s
						}
					}
					if (earliestNextUpdate != null) {
						((RevocationFreshnessStatus) status).addTokenAndRevocationNextUpdateTime(certificateToken, earliestNextUpdate);
					}
				}
			}
		}
	}

	private boolean noNextUpdateDefined(List<RevocationToken<?>> relatedRevocationTokens) {
		return relatedRevocationTokens.stream().noneMatch(revocationToken -> revocationToken.getNextUpdate() != null);
	}

	@Override
	public boolean checkAllPOECoveredByRevocationData() {
		return allPOECoveredByRevocationData().isEmpty();
	}

	/**
	 * Returns the status of the POE covered by revocation data check
	 *
	 * @return {@link RevocationFreshnessStatus}
	 */
	protected RevocationFreshnessStatus allPOECoveredByRevocationData() {
		RevocationFreshnessStatus status = new RevocationFreshnessStatus();
		Map<CertificateToken, List<CertificateToken>> orderedCertificateChains = getOrderedCertificateChains();
		for (Map.Entry<CertificateToken, List<CertificateToken>> entry : orderedCertificateChains.entrySet()) {
			CertificateToken firstChainCertificate = entry.getKey();
			Date lastCertUsageDate = getLatestTimestampUsageDate(firstChainCertificate);
			if (lastCertUsageDate != null) {
				checkRevocationForCertificateChainAgainstBestSignatureTime(entry.getValue(), lastCertUsageDate, status);
			}
		}
		if (!status.isEmpty()) {
			status.setMessage("Revocation data is missing for one or more POE(s).");
		}
		return status;
	}

	@Override
	public boolean checkAllTimestampsValid() {
		return allTimestampsValid().isEmpty();
	}

	/**
	 * Returns the status of the all timestamps valid check
	 *
	 * @return {@link TokenStatus}
	 */
	protected TokenStatus allTimestampsValid() {
		TokenStatus status = new TokenStatus();
		for (TimestampToken timestampToken : processedTimestamps) {
			if (!timestampToken.isSignatureIntact() || !timestampToken.isMessageImprintDataFound() ||
					!timestampToken.isMessageImprintDataIntact()) {
				status.addRelatedTokenAndErrorMessage(timestampToken, "Signature is not intact!");
			}
		}
		if (!status.isEmpty()) {
			status.setMessage("Broken timestamp(s) detected.");
		}
		return status;
	}

	@Override
	public boolean checkCertificateNotRevoked(CertificateToken certificateToken) {
		return certificateNotRevoked(certificateToken).isEmpty();
	}

	/**
	 * Returns the status of the certificate not revoked check
	 *
	 * @param certificateToken {@code CertificateToken} certificate to be checked
	 * @return {@link TokenStatus}
	 */
	protected TokenStatus certificateNotRevoked(CertificateToken certificateToken) {
		TokenStatus status = new TokenStatus();
		checkCertificateIsNotRevokedRecursively(certificateToken, poeTimes.get(certificateToken.getDSSIdAsString()), status);
		if (!status.isEmpty()) {
			status.setMessage("Revoked/Suspended certificate(s) detected.");
		}
		return status;
	}

	@Override
	public boolean checkAllSignatureCertificatesNotRevoked() {
		return allSignatureCertificatesNotRevoked().isEmpty();
	}

	/**
	 * Returns the status of the all signature certificates not revoked check
	 *
	 * @return {@link TokenStatus}
	 */
	protected TokenStatus allSignatureCertificatesNotRevoked() {
		TokenStatus status = new TokenStatus();
		for (AdvancedSignature signature : processedSignatures) {
			checkSignatureCertificatesNotRevoked(signature, status);
		}
		if (!status.isEmpty()) {
			status.setMessage("Revoked/Suspended certificate(s) detected.");
		}
		return status;
	}

	private void checkSignatureCertificatesNotRevoked(AdvancedSignature signature, TokenStatus status) {
		CertificateToken signingCertificate = signature.getSigningCertificateToken();
		if (signingCertificate != null) {
			checkCertificateIsNotRevokedRecursively(signingCertificate, poeTimes.get(signature.getId()), status);
		}
	}

	private boolean checkCertificateIsNotRevokedRecursively(CertificateToken certificateToken, List<POE> poeTimes) {
		return checkCertificateIsNotRevokedRecursively(certificateToken, poeTimes, null);
	}

	private boolean checkCertificateIsNotRevokedRecursively(CertificateToken certificateToken, List<POE> poeTimes, TokenStatus status) {
		Date lowestPOETime = getLowestPOETime(poeTimes);
		if (isSelfSignedOrTrustedAtTime(certificateToken, lowestPOETime)) {
			return true;

		} else if (!isRevocationDataNotRequired(certificateToken, lowestPOETime)) {
			List<RevocationToken<?>> relatedRevocationTokens = getRelatedRevocationTokens(certificateToken);
			// check only available revocation data in order to not duplicate
			// the method {@code checkAllRequiredRevocationDataPresent()}
			if (Utils.isCollectionNotEmpty(relatedRevocationTokens)) {
				// check if there is a best-signature-time before the revocation date
				for (RevocationToken<?> revocationToken : relatedRevocationTokens) {
					if (!getRevocationDataVerifier().checkCertificateNotRevoked(revocationToken, lowestPOETime)) {
						if (status != null) {
							status.addRelatedTokenAndErrorMessage(certificateToken, "Certificate is revoked/suspended!");
						}
						return false;
					}
				}
			}
		}

		CertificateToken issuer = getIssuer(certificateToken);
		if (issuer != null) {
			return checkCertificateIsNotRevokedRecursively(issuer, poeTimes, status);
		}
		return true;
	}

	private boolean isRevocationDataNotRequired(CertificateToken certToken, Date controlTime) {
		return getRevocationDataVerifier().isRevocationDataSkip(certToken, controlTime);
	}
	
	private boolean isSelfSignedOrTrustedAtTime(CertificateToken certToken, Date controlTime) {
		return isSelfSigned(certToken) || isTrustedAtTime(certToken, controlTime);
	}

	private boolean isSelfSigned(CertificateToken certToken) {
		return certToken.isSelfSigned();
	}

	private List<RevocationToken<?>> getRelatedRevocationTokens(CertificateToken certificateToken) {
		return getRevocationData(certificateToken);
	}

	private boolean isRevocationDataRefreshNeeded(CertificateToken certToken, Collection<RevocationToken<?>> revocations) {
		Context context = null;
		// get best-signature-time for b-level certificate chain
		Date refreshNeededAfterTime = getLatestBestSignatureTime(certToken);
		if (refreshNeededAfterTime != null) {
			context = Context.SIGNATURE;
		}
		// get last usage dates for the same timestamp certificate chain
		Date lastTimestampUsageTime = getLatestTimestampUsageDate(certToken);
		if (lastTimestampUsageTime != null) {
			if (context == null) {
				context = Context.TIMESTAMP;
			}
		}
		// return best POE for other cases
		if (refreshNeededAfterTime == null) {
			// shall not return null
			refreshNeededAfterTime = getLowestPOETime(certToken);
			if (context == null) {
				context = Context.REVOCATION;
			}
		}
		boolean freshRevocationDataFound = false;
		for (RevocationToken<?> revocationToken : revocations) {
			final List<CertificateToken> certificateTokenChain = toCertificateTokenChain(getCertChain(revocationToken));
			if (Utils.isCollectionEmpty(certificateTokenChain)) {
				LOG.debug("Certificate chain is not found for a revocation data '{}'!", revocationToken.getDSSIdAsString());
				continue;
			}

			final CertificateToken issuerCertificateToken = certificateTokenChain.iterator().next();
			if (isRevocationFresh(revocationToken, refreshNeededAfterTime, context)
					&& isRevocationIssuedAfterLastTimestampUsage(revocationToken, lastTimestampUsageTime, context)
					&& RevocationReason.CERTIFICATE_HOLD != revocationToken.getReason()
					&& isRevocationAcceptable(revocationToken, issuerCertificateToken, getLowestPOETime(issuerCertificateToken))
					&& hasValidPOE(revocationToken, certToken, issuerCertificateToken)) {
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

	private Date getLatestBestSignatureTime(CertificateToken certificateToken) {
		Date latestPOETime = null;
		for (Date bestSignatureTime : getBestSignatureTimes(certificateToken)) {
			if (latestPOETime == null || bestSignatureTime.after(latestPOETime)) {
				latestPOETime = bestSignatureTime;
			}
		}
		return latestPOETime;
	}

	private List<Date> getBestSignatureTimes(CertificateToken certificateToken) {
		List<AdvancedSignature> signatures = certificateSignaturesUsage.get(certificateToken);
		if (Utils.isCollectionEmpty(signatures)) {
			return Collections.emptyList();
		}
		final List<Date> bestSignatureTimes = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			Date poeTime = getLowestPOETime(poeTimes.get(signature.getId()));
			if (poeTime != null) {
				bestSignatureTimes.add(poeTime);
			}
		}
		return bestSignatureTimes;
	}

	private Date getLatestTimestampUsageDate(CertificateToken certificateToken) {
		return getLatestTime(timestampCertChainDates.get(certificateToken));
	}

	private Date getLatestTime(List<Date> dates) {
		if (Utils.isCollectionNotEmpty(dates)) {
			Date latestTime = null;
			for (Date date : dates) {
				if (latestTime == null || date.after(latestTime)) {
					latestTime = date;
				}
			}
			return latestTime;
		}
		return null;
	}
	
	private Date getLowestPOETime(Token token) {
		return getLowestPOETime(poeTimes.get(token.getDSSIdAsString()));
	}

	private Date getLowestPOETime(List<POE> poeList) {
		return getLowestPOE(poeList).getTime();
	}

	private POE getLowestPOE(List<POE> poeList) {
		if (Utils.isCollectionEmpty(poeList)) {
			throw new IllegalStateException("POE shall be defined before accessing the 'poeTimes' list!");
		}
		Iterator<POE> it = poeList.iterator();
		POE lowestPOE = it.next();
		while (it.hasNext()) {
			POE poe = it.next();
			if (poe.getTime().before(lowestPOE.getTime())) {
				lowestPOE = poe;
			}
		}
		return lowestPOE;
	}

	private boolean isRevocationFresh(RevocationToken<?> revocationToken, Date refreshNeededAfterTime, Context context) {
		return getRevocationDataVerifier().isRevocationDataFresh(revocationToken, refreshNeededAfterTime, context);
	}

	private boolean isRevocationIssuedAfterLastTimestampUsage(RevocationToken<?> revocationToken, Date lastTimestampUsage, Context context) {
		if (lastTimestampUsage == null) {
			return true;
		}
		return getRevocationDataVerifier().isRevocationDataFresh(revocationToken, lastTimestampUsage, context);
	}

	private boolean isRevocationAcceptable(RevocationToken<?> revocation, CertificateToken issuerCertificateToken, Date controlTime) {
		return getRevocationDataVerifier().isAcceptable(revocation, issuerCertificateToken,
				getCertificateTokenChain(issuerCertificateToken), controlTime);
	}
	
	private boolean hasValidPOE(RevocationToken<?> revocation, CertificateToken relatedCertToken, CertificateToken issuerCertToken) {
		if (revocation.getNextUpdate() != null && !hasPOEAfterThisUpdateAndBeforeNextUpdate(revocation)) {
			LOG.debug("There is no POE for the revocation '{}' after its production time and before the nextUpdate! " +
							"Certificate: {}", revocation.getDSSIdAsString(), relatedCertToken.getDSSIdAsString());
			return false;
		}
		// useful for short-life certificates (i.e. ocsp responder)
		if (issuerCertToken != null && !isTrustedAtUsageTime(issuerCertToken, Context.REVOCATION) && !hasPOEInTheValidityRange(issuerCertToken)) {
			LOG.debug("There is no POE for the revocation issuer '{}' for revocation '{}' within its validity range! " +
					"Certificate: {}", issuerCertToken.getDSSIdAsString(), revocation.getDSSIdAsString(), relatedCertToken.getDSSIdAsString());
			return false;
		}
		LOG.debug("The revocation '{}' has a valid POE. Certificate: {}", revocation.getDSSIdAsString(), relatedCertToken.getDSSIdAsString());
		return true;
	}
	
	private boolean hasPOEAfterThisUpdateAndBeforeNextUpdate(RevocationToken<?> revocation) {
		List<POE> poeTimeList = poeTimes.get(revocation.getDSSIdAsString());
		if (Utils.isCollectionNotEmpty(poeTimeList)) {
			for (POE poeTime : poeTimeList) {
				if (getRevocationDataVerifier().isAfterThisUpdateAndBeforeNextUpdate(revocation, poeTime.getTime())) {
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

	@Override
	public boolean checkAllSignatureCertificateHaveFreshRevocationData() {
		return allSignatureCertificateHaveFreshRevocationData().isEmpty();
	}

	/**
	 * Returns the status of the all signature certificates have fresh revocation data check
	 *
	 * @return {@link RevocationFreshnessStatus}
	 */
	protected RevocationFreshnessStatus allSignatureCertificateHaveFreshRevocationData() {
		RevocationFreshnessStatus status = new RevocationFreshnessStatus();
		for (AdvancedSignature signature : processedSignatures) {
			checkAtLeastOneRevocationDataPresentAfterBestSignatureTime(signature, status);
		}
		if (!status.isEmpty()) {
			status.setMessage("Fresh revocation data is missing for one or more certificate(s).");
		}
		return status;
	}

	private void checkAtLeastOneRevocationDataPresentAfterBestSignatureTime(AdvancedSignature signature, RevocationFreshnessStatus status) {
		CertificateToken signingCertificateToken = signature.getSigningCertificateToken();
		Map<CertificateToken, List<CertificateToken>> orderedCertificateChains = getOrderedCertificateChains();
		for (Map.Entry<CertificateToken, List<CertificateToken>> entry : orderedCertificateChains.entrySet()) {
			CertificateToken firstChainCertificate = entry.getKey();
			if (firstChainCertificate.equals(signingCertificateToken)) {
				Date bestSignatureTime = getEarliestTimestampTime();
				checkRevocationForCertificateChainAgainstBestSignatureTime(entry.getValue(), bestSignatureTime, status);
			}
		}
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
	public boolean checkAllSignaturesNotExpired() {
		return allSignaturesNotExpired().isEmpty();
	}

	/**
	 * Returns the status of the all signatures not expired check
	 *
	 * @return {@link SignatureStatus}
	 */
	protected SignatureStatus allSignaturesNotExpired() {
		SignatureStatus status = new SignatureStatus();
		for (AdvancedSignature signature : processedSignatures) {
			checkSignatureNotExpired(signature, status);
		}
		if (!status.isEmpty()) {
			status.setMessage("Expired signature found.");
		}
		return status;
	}

	@Override
	public boolean checkCertificateNotExpired(CertificateToken certificateToken) {
		return certificateNotExpired(certificateToken).isEmpty();
	}

	/**
	 * Returns the status of the all signatures not expired check
	 *
	 * @return {@link SignatureStatus}
	 */
	protected TokenStatus certificateNotExpired(CertificateToken certificateToken) {
		TokenStatus status = new TokenStatus();
		checkCertificateNotExpired(certificateToken, status);
		if (!status.isEmpty()) {
			status.setMessage("Expired certificate found.");
		}
		return status;
	}

	private void checkSignatureNotExpired(AdvancedSignature signature, SignatureStatus status) {
		CertificateToken signingCertificate = signature.getSigningCertificateToken();
		if (signingCertificate != null) {
			boolean signatureNotExpired = verifyCertificateTokenNotExpired(signingCertificate, poeTimes.get(signature.getId()));
			if (!signatureNotExpired) {
				status.addRelatedTokenAndErrorMessage(signature, String.format("The signing certificate has expired " +
								"and there is no POE during its validity range : [%s - %s]!",
						DSSUtils.formatDateToRFC(signingCertificate.getNotBefore()),
						DSSUtils.formatDateToRFC(signingCertificate.getNotAfter())));
			}
		}
	}

	private void checkCertificateNotExpired(CertificateToken certificateToken, TokenStatus status) {
		boolean certificateNotExpired = verifyCertificateTokenNotExpired(certificateToken, poeTimes.get(certificateToken.getDSSIdAsString()));
		if (!certificateNotExpired) {
			status.addRelatedTokenAndErrorMessage(certificateToken, String.format("The signing certificate has expired " +
							"and there is no POE during its validity range : [%s - %s]!",
					DSSUtils.formatDateToRFC(certificateToken.getNotBefore()),
					DSSUtils.formatDateToRFC(certificateToken.getNotAfter())));
		}
	}

	private boolean verifyCertificateTokenNotExpired(CertificateToken certificateToken, List<POE> poeTimeList) {
		if (Utils.isCollectionNotEmpty(poeTimeList) && certificateToken.getNotAfter() != null) {
			for (POE poeTime : poeTimeList) {
				if (poeTime.getTime() != null && !poeTime.getTime().after(certificateToken.getNotAfter())) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public boolean checkAllSignaturesAreYetValid() {
		return allSignaturesAreYetValid().isEmpty();
	}

	/**
	 * Returns the status of the all signatures are yet valid check
	 *
	 * @return {@link SignatureStatus}
	 */
	protected SignatureStatus allSignaturesAreYetValid() {
		SignatureStatus status = new SignatureStatus();
		for (AdvancedSignature signature : processedSignatures) {
			checkSignatureIsYetValid(signature, status);
		}
		if (!status.isEmpty()) {
			status.setMessage("Not yet valid signature found.");
		}
		return status;
	}

	@Override
	public boolean checkCertificateIsYetValid(CertificateToken certificateToken) {
		return certificateNotExpired(certificateToken).isEmpty();
	}

	/**
	 * Returns the status of the all signatures not expired check
	 *
	 * @return {@link SignatureStatus}
	 */
	protected TokenStatus certificateIsYetValid(CertificateToken certificateToken) {
		TokenStatus status = new TokenStatus();
		checkCertificateIsYetValid(certificateToken, status);
		if (!status.isEmpty()) {
			status.setMessage("Not yet valid certificate found.");
		}
		return status;
	}

	private void checkSignatureIsYetValid(AdvancedSignature signature, SignatureStatus status) {
		CertificateToken signingCertificate = signature.getSigningCertificateToken();
		if (signingCertificate != null) {
			boolean signatureNotExpired = verifyCertificateTokenIsYetValid(signingCertificate, poeTimes.get(signature.getId()));
			if (!signatureNotExpired) {
				status.addRelatedTokenAndErrorMessage(signature, String.format(
						"The signing certificate with validity range [%s - %s] is not yet valid at signing time!",
						DSSUtils.formatDateToRFC(signingCertificate.getNotBefore()),
						DSSUtils.formatDateToRFC(signingCertificate.getNotAfter())));
			}
		}
	}

	private void checkCertificateIsYetValid(CertificateToken certificateToken, TokenStatus status) {
		boolean certificateNotExpired = verifyCertificateTokenIsYetValid(certificateToken, poeTimes.get(certificateToken.getDSSIdAsString()));
		if (!certificateNotExpired) {
			status.addRelatedTokenAndErrorMessage(certificateToken, String.format(
					"The signing certificate with validity range [%s - %s] is not yet valid at signing time!",
					DSSUtils.formatDateToRFC(certificateToken.getNotBefore()),
					DSSUtils.formatDateToRFC(certificateToken.getNotAfter())));
		}
	}

	private boolean verifyCertificateTokenIsYetValid(CertificateToken certificateToken, List<POE> poeTimeList) {
		if (Utils.isCollectionNotEmpty(poeTimeList) && certificateToken.getNotAfter() != null) {
			for (POE poeTime : poeTimeList) {
				if (poeTime.getTime() != null && !poeTime.getTime().before(certificateToken.getNotBefore())) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public Set<AdvancedSignature> getProcessedSignatures() {
		return Collections.unmodifiableSet(processedSignatures);
	}

	@Override
	public Set<CertificateToken> getProcessedCertificates() {
		return Collections.unmodifiableSet(processedCertificates);
	}

	@Override
	public Set<RevocationToken<?>> getProcessedRevocations() {
		return Collections.unmodifiableSet(processedRevocations);
	}

	@Override
	public Set<TimestampToken> getProcessedTimestamps() {
		return Collections.unmodifiableSet(processedTimestamps);
	}

	@Override
	public Set<EvidenceRecord> getProcessedEvidenceRecords() {
		return Collections.unmodifiableSet(processedEvidenceRecords);
	}

	private <T extends Token> boolean isTrustedAtUsageTime(T token) {
		return isTrustedAtUsageTime(token, null);
	}

	private <T extends Token> boolean isTrustedAtUsageTime(T token, Context context) {
		if (token instanceof CertificateToken) {
			List<Date> bestSignatureTimes = getBestSignatureTimes((CertificateToken) token);
			if (Utils.isCollectionNotEmpty(bestSignatureTimes)) {
				for (Date date : bestSignatureTimes) {
					if (isTrustedAtTime(token, date, context)) {
						return true;
					}
				}
			} else {
				Date lowestPOETime = getLowestPOETime(token);
				return isTrustedAtTime(token, lowestPOETime, context);
			}
		}
		return false;
	}

	private <T extends Token> boolean isTrustedAtTime(T token, Date controlTime) {
		return isTrustedAtTime(token, controlTime, null);
	}

	private <T extends Token> boolean isTrustedAtTime(T token, Date controlTime, Context context) {
		return token instanceof CertificateToken && getTrustAnchorVerifier().isTrustedAtTime((CertificateToken) token, controlTime, context);
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
				List<RevocationToken<?>> revocationTokens = getRelatedRevocationTokens((CertificateToken) token);
				for (RevocationToken<?> revocationToken : revocationTokens) {
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
	private static class POE {

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
