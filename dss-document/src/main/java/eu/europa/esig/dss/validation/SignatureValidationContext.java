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
import java.util.Collection;
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

		for (CertificateToken certificateToken : processedCertificates) {
			validationCertificatePool.getInstance(certificateToken, CertificateSourceType.UNKNOWN);
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
	 * @param token
	 *            the token for which the issuer must be obtained.
	 * @return the issuer certificate token of the given token or null if not found.
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private CertificateToken getIssuerCertificate(final Token token) throws DSSException {

		if (token.isTrusted()) {

			// When the token is trusted the check of the issuer token is not needed so null is returned. Only a
			// certificate token can be trusted.
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
	 * @param token
	 *            {@code CertificateToken} for which the issuer is sought.
	 * @return {@code CertificateToken} representing the issuer certificate or null.
	 */
	private CertificateToken getIssuerFromAIA(final CertificateToken token) {
		LOG.info("Retrieving {} certificate's issuer using AIA.", token.getAbbreviation());
		Collection<CertificateToken> issuerCerts = DSSUtils.loadIssuerCertificates(token, dataLoader);
		if (Utils.isCollectionNotEmpty(issuerCerts)) {
			CertificateToken issuerCertToken = null;
			for (CertificateToken issuerCert : issuerCerts) {
				CertificateToken issuerCertFromAia = validationCertificatePool.getInstance(issuerCert, CertificateSourceType.AIA);
				if (token.isSignedBy(issuerCertFromAia)) {
					issuerCertToken = issuerCertFromAia;
				} else {
					addCertificateTokenForVerification(issuerCertFromAia);
				}
			}
			if (issuerCertToken == null) {
				LOG.info("The retrieved certificate(s) using AIA does not sign the certificate {}.", token.getAbbreviation());
			}
			return issuerCertToken;
		} else {
			LOG.info("The issuer certificate cannot be loaded using AIA.");
		}
		return null;
	}

	/**
	 * This function retrieves the issuer certificate from the validation pool (this pool should contain trusted
	 * certificates). The check is made if the token is well signed by
	 * the retrieved certificate.
	 *
	 * @param token
	 *            token for which the issuer have to be found
	 * @param issuerX500Principal
	 *            issuer's subject distinguished name
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
	 * Adds a new token to the list of tokens to verify only if it was not already verified.
	 *
	 * @param token
	 *            token to verify
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
					final List<RevocationToken> revocationTokens = getRevocationData((CertificateToken) token);
					addRevocationTokensForVerification(revocationTokens);
				}

			}
		} while (token != null);
	}

	/**
	 * Retrieves the revocation data from signature (if exists) or from the online sources. The issuer certificate must
	 * be provided, the underlining library (bouncy castle) needs
	 * it to build the request.
	 *
	 * @param certToken
	 * @return
	 */
	private List<RevocationToken> getRevocationData(final CertificateToken certToken) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("Checking revocation data for: " + certToken.getDSSIdAsString());
		}
		if (certToken.isSelfSigned() || certToken.isTrusted()) {
			// This check is not needed for the trust anchor.
			return Collections.emptyList();
		} else if (certToken.getIssuerToken() == null) {
			// It is not possible to check the revocation data without its signing certificate;
			LOG.warn("Cannot retrieve revocation data (issuer is unknown)");
			return Collections.emptyList();
		}

		if (DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken)) {
			certToken.extraInfo().infoOCSPNoCheckPresent();
			return Collections.emptyList();
		}

		List<RevocationToken> revocations = new ArrayList<RevocationToken>();

		// ALL Embedded revocation data
		OCSPAndCRLCertificateVerifier offlineVerifier = new OCSPAndCRLCertificateVerifier(signatureCRLSource, signatureOCSPSource, validationCertificatePool);
		RevocationToken ocspToken = offlineVerifier.checkOCSP(certToken);
		if (ocspToken != null) {
			revocations.add(ocspToken);
		}

		RevocationToken crlToken = offlineVerifier.checkCRL(certToken);
		if (crlToken != null) {
			revocations.add(crlToken);
		}

		// Online resources (OCSP and CRL if OCSP doesn't reply)
		final OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier(crlSource, ocspSource, validationCertificatePool);
		final RevocationToken onlineRevocationToken = onlineVerifier.check(certToken);
		// CRL can already exist in the signature
		if (onlineRevocationToken != null && !revocations.contains(onlineRevocationToken)) {
			revocations.add(onlineRevocationToken);
		}

		if (revocations.isEmpty()) {
			LOG.warn("No revocation found for certificate {}", certToken.getDSSIdAsString());
		}

		return revocations;
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
