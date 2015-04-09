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

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.crl.ListCRLSource;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.ocsp.ListOCSPSource;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;

public abstract class DefaultAdvancedSignature implements AdvancedSignature {

	/**
	 * This is the reference to the global (external) pool of certificates. All encapsulated certificates in the signature are added to this pool. See {@link
	 * eu.europa.esig.dss.x509.CertificatePool}
	 */
	protected final CertificatePool certPool;

	/**
	 * In the case of a non AdES signature the signing certificate is not mandatory within the signature and can be provided by the driving application.
	 */
	protected CertificateToken providedSigningCertificateToken;

	/**
	 * In case of a detached signature this is the signed document.
	 */
	protected List<DSSDocument> detachedContents;

	/**
	 * This variable contains the result of the signature mathematical validation. It is initialised when the method {@code checkSignatureIntegrity} is called.
	 */
	protected SignatureCryptographicVerification signatureCryptographicVerification;

	/**
	 * The reference to the object containing all candidates to the signing certificate.
	 */
	protected CandidatesForSigningCertificate candidatesForSigningCertificate;

	// Enclosed content timestamps.
	protected List<TimestampToken> contentTimestamps;

	// Enclosed signature timestamps.
	protected transient List<TimestampToken> signatureTimestamps;

	// Enclosed SignAndRefs timestamps.
	protected List<TimestampToken> sigAndRefsTimestamps;

	// Enclosed RefsOnly timestamps.
	protected List<TimestampToken> refsOnlyTimestamps;

	// This variable contains the list of enclosed archive signature timestamps.
	protected List<TimestampToken> archiveTimestamps;

	// Cached {@code OfflineCRLSource}
	protected OfflineCRLSource offlineCRLSource;

	// Cached {@code OfflineOCSPSource}
	protected OfflineOCSPSource offlineOCSPSource;
	private AdvancedSignature masterSignature;

	/**
	 * @param certPool can be null
	 */
	protected DefaultAdvancedSignature(final CertificatePool certPool) {
		this.certPool = certPool;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return detachedContents;
	}

	@Override
	public void setDetachedContents(final DSSDocument... detachedContents) {

		for (final DSSDocument detachedContent : detachedContents) {

			if (detachedContent != null) {

				if (this.detachedContents == null) {

					this.detachedContents = new ArrayList<DSSDocument>();
				}
				this.detachedContents.add(detachedContent);
			}
		}
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}

	/**
	 * @return the upper level for which data have been found. Doesn't mean any validity of the data found. Null if unknown.
	 */
	@Override
	public SignatureLevel getDataFoundUpToLevel() {

		final SignatureLevel[] signatureLevels = getSignatureLevels();
		final SignatureLevel dataFoundUpToProfile = getDataFoundUpToProfile(signatureLevels);
		return dataFoundUpToProfile;
	}

	/**
	 * This method returns the {@code SignatureLevel} which was reached.
	 *
	 * @param signatureLevels the array of the all levels associated with the given signature type
	 * @return {@code SignatureLevel}
	 */
	private SignatureLevel getDataFoundUpToProfile(final SignatureLevel... signatureLevels) {

		for (int ii = signatureLevels.length - 1; ii >= 0; ii--) {

			final SignatureLevel signatureLevel = signatureLevels[ii];
			if (isDataForSignatureLevelPresent(signatureLevel)) {
				return signatureLevel;
			}
		}
		return null;
	}

	/**
	 * This method validates the signing certificate and all timestamps.
	 *
	 * @return signature validation context containing all certificates and revocation data used during the validation process.
	 */
	public ValidationContext getSignatureValidationContext(final CertificateVerifier certificateVerifier) {

		final ValidationContext validationContext = new SignatureValidationContext();
		final List<CertificateToken> certificates = getCertificates();
		for (final CertificateToken certificate : certificates) {

			validationContext.addCertificateTokenForVerification(certificate);
		}
		prepareTimestamps(validationContext);
		certificateVerifier.setSignatureCRLSource(new ListCRLSource(getCRLSource()));
		certificateVerifier.setSignatureOCSPSource(new ListOCSPSource(getOCSPSource()));
		// certificateVerifier.setAdjunctCertSource(getCertificateSource());
		validationContext.initialize(certificateVerifier);
		validationContext.validate();
		return validationContext;
	}

	/**
	 * This method returns all certificates used during the validation process. If a certificate is already present within the signature then it is ignored.
	 *
	 * @param validationContext validation context containing all information about the validation process of the signing certificate and time-stamps
	 * @return set of certificates not yet present within the signature
	 */
	public Set<CertificateToken> getCertificatesForInclusion(final ValidationContext validationContext) {

		final Set<CertificateToken> certificates = new HashSet<CertificateToken>();
		final List<CertificateToken> certWithinSignatures = getCertificatesWithinSignatureAndTimestamps();
		for (final CertificateToken certificateToken : validationContext.getProcessedCertificates()) {
			if (certWithinSignatures.contains(certificateToken)) {
				continue;
			}
			certificates.add(certificateToken);
		}
		return certificates;
	}

	public List<CertificateToken> getCertificatesWithinSignatureAndTimestamps() {

		final List<CertificateToken> certWithinSignatures = new ArrayList<CertificateToken>();
		certWithinSignatures.addAll(getCertificates());
		for (final TimestampToken timestampToken : getSignatureTimestamps()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getArchiveTimestamps()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getContentTimestamps()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getTimestampsX1()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getTimestampsX2()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		return certWithinSignatures;
	}

	/**
	 * This method returns revocation values (ocsp and crl) that will be included in the LT profile.
	 *
	 * @param validationContext {@code ValidationContext} contains all the revocation data retrieved during the validation process.
	 * @return {@code RevocationDataForInclusion}
	 */
	public RevocationDataForInclusion getRevocationDataForInclusion(final ValidationContext validationContext) {

		//TODO: to be checked: there can be also CRL and OCSP in TimestampToken CMS data
		final Set<RevocationToken> revocationTokens = validationContext.getProcessedRevocations();
		final OfflineCRLSource crlSource = getCRLSource();
		final List<X509CRL> containedX509CRLs = crlSource.getContainedX509CRLs();
		final OfflineOCSPSource ocspSource = getOCSPSource();
		final List<BasicOCSPResp> containedBasicOCSPResponses = ocspSource.getContainedOCSPResponses();
		final List<CRLToken> crlTokens = new ArrayList<CRLToken>();
		final List<OCSPToken> ocspTokens = new ArrayList<OCSPToken>();
		for (final RevocationToken revocationToken : revocationTokens) {

			if (revocationToken instanceof CRLToken) {

				final CRLToken crlToken = (CRLToken) revocationToken;
				final X509CRL x509crl = crlToken.getX509crl();
				final boolean tokenIn = containedX509CRLs.contains(x509crl);
				if (!tokenIn) {

					crlTokens.add(crlToken);
				}
			} else if (revocationToken instanceof OCSPToken) {

				final boolean tokenIn = DSSRevocationUtils.isTokenIn(revocationToken, containedBasicOCSPResponses);
				if (!tokenIn) {

					final OCSPToken ocspToken = (OCSPToken) revocationToken;
					ocspTokens.add(ocspToken);
				}
			} else {
				throw new DSSException("Unknown type for revocationToken: " + revocationToken.getClass().getName());
			}
		}
		return new RevocationDataForInclusion(crlTokens, ocspTokens);
	}

	@Override
	public void setMasterSignature(final AdvancedSignature masterSignature) {
		this.masterSignature = masterSignature;
	}

	@Override
	public AdvancedSignature getMasterSignature() {
		return masterSignature;
	}

	public static class RevocationDataForInclusion {

		public final List<CRLToken> crlTokens;
		public final List<OCSPToken> ocspTokens;

		public RevocationDataForInclusion(final List<CRLToken> crlTokens, final List<OCSPToken> ocspTokens) {

			this.crlTokens = crlTokens;
			this.ocspTokens = ocspTokens;
		}

		public boolean isEmpty() {

			return crlTokens.isEmpty() && ocspTokens.isEmpty();
		}
	}

	@Override
	public CertificateToken getProvidedSigningCertificateToken() {
		return providedSigningCertificateToken;
	}

	@Override
	public void setProvidedSigningCertificateToken(final CertificateToken certificateToken) {
		this.providedSigningCertificateToken = certificateToken;
	}

	@Override
	public CertificateToken getSigningCertificateToken() {

		// This ensures that the variable candidatesForSigningCertificate has been initialized
		candidatesForSigningCertificate = getCandidatesForSigningCertificate();
		// This ensures that the variable signatureCryptographicVerification has been initialized
		signatureCryptographicVerification = checkSignatureIntegrity();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		if (theCertificateValidity != null) {

			if (theCertificateValidity.isValid()) {

				final CertificateToken signingCertificateToken = theCertificateValidity.getCertificateToken();
				return signingCertificateToken;
			}
		}
		final CertificateValidity theBestCandidate = candidatesForSigningCertificate.getTheBestCandidate();
		return theBestCandidate == null ? null : theBestCandidate.getCertificateToken();
	}

	/**
	 * This method adds to the {@code ValidationContext} all timestamps to be validated.
	 *
	 * @param validationContext {@code ValidationContext} to which the timestamps must be added
	 */
	@Override
	public void prepareTimestamps(final ValidationContext validationContext) {

		/*
		 * This validates the signature timestamp tokens present in the signature.
		 */
		for (final TimestampToken timestampToken : getContentTimestamps()) {
			validationContext.addTimestampTokenForVerification(timestampToken);
		}

		/*
		 * This validates the signature timestamp tokens present in the signature.
		 */
		for (final TimestampToken timestampToken : getSignatureTimestamps()) {
			validationContext.addTimestampTokenForVerification(timestampToken);
		}

		/*
		 * This validates the SigAndRefs timestamp tokens present in the signature.
		 */
		for (final TimestampToken timestampToken : getTimestampsX1()) {
			validationContext.addTimestampTokenForVerification(timestampToken);
		}

		/*
		 * This validates the RefsOnly timestamp tokens present in the signature.
		 */
		for (final TimestampToken timestampToken : getTimestampsX2()) {
			validationContext.addTimestampTokenForVerification(timestampToken);
		}

		/*
		 * This validates the archive timestamp tokens present in the signature.
		 */
		for (final TimestampToken timestampToken : getArchiveTimestamps()) {
			validationContext.addTimestampTokenForVerification(timestampToken);
		}
	}

	/**
	 * This method adds all timestamps to be validated.
	 */
	@Override
	public void validateTimestamps() {

		/*
		 * This validates the content-timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getContentTimestamps()) {

			final byte[] timestampBytes = getContentTimestampData(timestampToken);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the signature timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getSignatureTimestamps()) {

			final byte[] timestampBytes = getSignatureTimestampData(timestampToken, null);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the SigAndRefs timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getTimestampsX1()) {

			final byte[] timestampBytes = getTimestampX1Data(timestampToken, null);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the RefsOnly timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getTimestampsX2()) {

			final byte[] timestampBytes = getTimestampX2Data(timestampToken, null);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the archive timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getArchiveTimestamps()) {

			final byte[] timestampData = getArchiveTimestampData(timestampToken, null);
			timestampToken.matchData(timestampData);
		}
	}

	@Override
	public String validateStructure() {
		return null;
	}
}

