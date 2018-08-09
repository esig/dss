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
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

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

	// External OCSP source.
	private OCSPSource ocspSource;

	// External CRL source.
	private CRLSource crlSource;

	// CRLs from the signature.
	private CRLSource signatureCRLSource;

	// OCSP from the signature.
	private OCSPSource signatureOCSPSource;

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
		if (validationCertificatePool == null) {
			throw new NullPointerException();
		}
		this.validationCertificatePool = validationCertificatePool;
	}

	/**
	 * @param certificateVerifier
	 *            The certificates verifier (eg: using the TSL as list of trusted certificates).
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
	 * This method returns the issuer certificate (the certificate which was used to
	 * sign the token) of the given token.
	 *
	 * @param token
	 *              the token for which the issuer must be obtained.
	 * @return the issuer certificate token of the given token or null if not found.
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private CertificateToken getIssuerCertificate(final Token token) throws DSSException {
		if (isTrusted(token)) {
			// When the token is trusted the check of the issuer token is not needed so null
			// is returned. Only a certificate token can be trusted.
			return null;
		}

		CertificateToken issuerCertificateToken = validationCertificatePool.getIssuer(token);

		if ((issuerCertificateToken == null) && (token instanceof CertificateToken)) {
			issuerCertificateToken = getIssuerFromAIA((CertificateToken) token);
		}

		if ((issuerCertificateToken == null) && (token instanceof TimestampToken)) {
			issuerCertificateToken = getTSACertificate((TimestampToken) token);
		}

		if (issuerCertificateToken == null) {
			token.extraInfo().infoTheSigningCertNotFound();
		}
//		if ((issuerCertificateToken != null) && !issuerCertificateToken.isTrusted() && !issuerCertificateToken.isSelfSigned()
//				&& !token.equals(issuerCertificateToken)) {
			// The full chain is retrieved for each certificate
//			getIssuerCertificate(issuerCertificateToken);
//		}
		return issuerCertificateToken;
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
						LOG.info("CERT ISSUER    : " + token.getIssuerX500Principal().toString());
						LOG.info("ISSUER SUBJECT : " + candidate.getSubjectX500Principal().toString());
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
						LOG.trace("Token was already in the list {}:{}", new Object[] { token.getClass().getSimpleName(), token.getAbbreviation() });
					}
					return false;
				}

				tokensToProcess.put(token, null);
				if (traceEnabled) {
					LOG.trace("+ New {} to check: {}", new Object[] { token.getClass().getSimpleName(), token.getAbbreviation() });
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

	@Override
	public void validate() throws DSSException {
		Token token = getNotYetVerifiedToken();
		while (token != null) {
			/**
			 * Gets the issuer certificate of the Token and checks its signature
			 */
			final CertificateToken issuerCertToken = getIssuerCertificate(token);
			if (issuerCertToken != null) {
				addCertificateTokenForVerification(issuerCertToken);
			}

			if (token instanceof CertificateToken) {
				final List<RevocationToken> revocationTokens = getRevocationData((CertificateToken) token);
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
	 * @return
	 */
	private List<RevocationToken> getRevocationData(final CertificateToken certToken) {

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

		if (revocations.isEmpty()) {
			// Online resources (OCSP and CRL if OCSP doesn't reply)
			final OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier(crlSource, ocspSource, validationCertificatePool);
			final RevocationToken onlineRevocationToken = onlineVerifier.check(certToken);
			// CRL can already exist in the signature
			if (onlineRevocationToken != null && !revocations.contains(onlineRevocationToken)) {
				revocations.add(onlineRevocationToken);
			}
		}

		if (revocations.isEmpty()) {
			LOG.warn("No revocation found for certificate {}", certToken.getDSSIdAsString());
		}

		return revocations;
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

	private boolean isRevocationDataNotRequired(CertificateToken certToken) {
		return certToken.isSelfSigned() || isTrusted(certToken) || DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken);
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

	private boolean isTrusted(Token token) {
		return token instanceof CertificateToken && validationCertificatePool.isTrusted((CertificateToken) token);
	}

}
