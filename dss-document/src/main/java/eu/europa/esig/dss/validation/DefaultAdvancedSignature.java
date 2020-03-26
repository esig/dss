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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.CertificateReorderer;
import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CertificateIdentifier;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.validation.timestamp.TimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public abstract class DefaultAdvancedSignature implements AdvancedSignature {

	private static final long serialVersionUID = 6452189007886779360L;

	private static final Logger LOG = LoggerFactory.getLogger(DefaultAdvancedSignature.class);

	/**
	 * This is the reference to the global (external) pool of certificates. All encapsulated certificates in the signature are added to this pool. See
	 * {@link eu.europa.esig.dss.spi.x509.CertificatePool}
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
	 * In case of a ASiC signature this is the archive or manifest content.
	 */
	private List<DSSDocument> containerContents;
	
	/**
	 * In case of a ASiC-E signature this is the list of found manifest files.
	 */
	protected List<ManifestFile> manifestFiles;

	/**
	 * This variable contains a list of reference validations (reference tag for
	 * XAdES or message-digest for CAdES)
	 */
	protected List<ReferenceValidation> referenceValidations;

	/**
	 * This variable contains the result of the signature mathematical validation. It is initialised when the method
	 * {@code checkSignatureIntegrity} is called.
	 */
	protected SignatureCryptographicVerification signatureCryptographicVerification;

	protected String structureValidation;

	/**
	 * The reference to the object containing all candidates to the signing certificate.
	 */
	protected CandidatesForSigningCertificate candidatesForSigningCertificate;

	// Cached {@code SignatureCertificateSource}
	protected SignatureCertificateSource offlineCertificateSource;

	// Cached {@code OfflineCRLSource}
	protected OfflineCRLSource signatureCRLSource;

	// Cached {@code OfflineOCSPSource}
	protected OfflineOCSPSource signatureOCSPSource;

	// Cached {@code TimestampSource}
	protected TimestampSource signatureTimestampSource;

	private AdvancedSignature masterSignature;

	protected SignaturePolicy signaturePolicy;

	private List<SignatureScope> signatureScopes;

	private String signatureFilename;
	
	/*
	 * Unique signature identifier
	 */
	protected SignatureIdentifier signatureIdentifier;
	
	/**
	 * Build and defines {@code signatureIdentifier} value
	 */
	protected abstract SignatureIdentifier buildSignatureIdentifier();

	/**
	 * @param certPool
	 *            can be null
	 */
	protected DefaultAdvancedSignature(final CertificatePool certPool) {
		this.certPool = certPool;
	}

	@Override
	public String getSignatureFilename() {
		return signatureFilename;
	}

	@Override
	public void setSignatureFilename(String signatureFilename) {
		this.signatureFilename = signatureFilename;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return detachedContents;
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}
	
	@Override
	public List<DSSDocument> getContainerContents() {
		return containerContents;
	}
	
	@Override
	public void setContainerContents(List<DSSDocument> containerContents) {
		this.containerContents = containerContents;
	}
	
	@Override
	public void setManifestFiles(List<ManifestFile> manifestFiles) {
		this.manifestFiles = manifestFiles;
	}
	
	@Override
	public SignatureIdentifier getDSSId() {
		if (signatureIdentifier == null) {
			signatureIdentifier = buildSignatureIdentifier();
		}
		return signatureIdentifier;
	}
	
	@Override
	public String getId() {
		return getDSSId().asXmlId();
	}

	@Override
	public List<DSSDocument> getManifestedDocuments() {
		if (Utils.isCollectionEmpty(manifestFiles) || Utils.isCollectionEmpty(containerContents)) {
			return Collections.emptyList();
		}
		List<DSSDocument> foundManifestedDocuments = new ArrayList<>();
		for (ManifestFile manifestFile : manifestFiles) {
			if (Utils.areStringsEqual(manifestFile.getSignatureFilename(), signatureFilename)) {
				for (DSSDocument document : containerContents) {
					for (ManifestEntry entry : manifestFile.getEntries()) {
						if (Utils.areStringsEqual(entry.getFileName(), document.getName())) {
							foundManifestedDocuments.add(document);
						}
					}
				}
				break;
			}
		}
		return foundManifestedDocuments;
	}
	
	/**
	 * @return the upper level for which data have been found. Doesn't mean any validity of the data found. Null if
	 *         unknown.
	 */
	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		final SignatureLevel[] signatureLevels = getSignatureLevels();
		final SignatureLevel dataFoundUpToProfile = getDataFoundUpToProfile(signatureLevels);
		return dataFoundUpToProfile;
	}
	
	@Override
	public ListCertificateSource getCompleteCertificateSource() {
		ListCertificateSource certificateSource = new ListCertificateSource(getCertificateSource());
		certificateSource.addAll(getTimestampSource().getTimestampCertificateSources());
		return certificateSource;
	}
	
	@Override
	public ListRevocationSource getCompleteCRLSource() {
		ListRevocationSource crlSource = new ListRevocationSource(getCRLSource());
		crlSource.addAll(getTimestampSource().getTimestampCRLSources());
		return crlSource;
	}

	@Override
	public ListRevocationSource getCompleteOCSPSource() {
		ListRevocationSource ocspSource = new ListRevocationSource(getOCSPSource());
		ocspSource.addAll(getTimestampSource().getTimestampOCSPSources());
		return ocspSource;
	}

	/**
	 * This method returns the {@code SignatureLevel} which was reached.
	 *
	 * @param signatureLevels
	 *            the array of the all levels associated with the given signature type
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
	 * @return signature validation context containing all certificates and
	 *         revocation data used during the validation process.
	 */
	public ValidationContext getSignatureValidationContext(final CertificateVerifier certificateVerifier) {

		final ValidationContext validationContext = new SignatureValidationContext(certPool);
		
		certificateVerifier.setSignatureCRLSource(getCompleteCRLSource());
		certificateVerifier.setSignatureOCSPSource(getCompleteOCSPSource());
		
		validationContext.initialize(certificateVerifier);

		if (providedSigningCertificateToken != null) {
			validationContext.addCertificateTokenForVerification(providedSigningCertificateToken);
		}
		final List<CertificateToken> certificates = getCertificates();
		for (final CertificateToken certificate : certificates) {
			validationContext.addCertificateTokenForVerification(certificate);
		}
		prepareTimestamps(validationContext);
		validationContext.validate();

		checkTimestamps(certificateVerifier, validationContext);
		checkAllRevocationDataPresent(certificateVerifier, validationContext);
		checkAllTimestampsCoveredByRevocationData(certificateVerifier, validationContext);
		checkAllCertificatesNotRevoked(certificateVerifier, validationContext);
		checkRevocationThisUpdateIsAfterBestSignatureTime(certificateVerifier, validationContext);

		return validationContext;
	}

	private void checkTimestamps(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		try {
			validationContext.checkAllTimestampsValid();
		} catch (DSSException e) {
			Alert<Exception> alert = certificateVerifier.getAlertOnInvalidTimestamp();
			String message = String.format("Broken timestamp detected. Cause : %s", e.getMessage());
			alert.alert(new DSSException(message, e));
		}
	}

	private void checkAllRevocationDataPresent(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		try {
			validationContext.checkAllRequiredRevocationDataPresent();
		} catch (DSSException e) {
			Alert<Exception> alert = certificateVerifier.getAlertOnMissingRevocationData();
			String message = String.format("Revocation data is missing. Cause : %s", e.getMessage());
			alert.alert(new DSSException(message, e));
		}
	}

	private void checkAllTimestampsCoveredByRevocationData(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		try {
			validationContext.checkAllPOECoveredByRevocationData();
		} catch (DSSException e) {
			Alert<Exception> alert = certificateVerifier.getAlertOnUncoveredPOE();
			String message = String.format("A POE is not covered by a usable revocation data. Cause : %s", e.getMessage());
			alert.alert(new DSSException(message, e));
		}
	}

	private void checkAllCertificatesNotRevoked(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		try {
			validationContext.checkAllCertificatesValid();
		} catch (DSSException e) {
			Alert<Exception> alert = certificateVerifier.getAlertOnRevokedCertificate();
			String message = String.format("Revoked certificate detected. Cause : %s", e.getMessage());
			alert.alert(new DSSException(message, e));
		}
	}

	private void checkRevocationThisUpdateIsAfterBestSignatureTime(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		try {
			CertificateToken signingCertificateToken = getSigningCertificateToken();
			validationContext.checkAtLeastOneRevocationDataPresentAfterBestSignatureTime(signingCertificateToken);
		} catch (DSSException e) {
			Alert<Exception> alert = certificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime();
			String message = String.format("No fresh revocation data found. Cause : %s", e.getMessage());
			alert.alert(new DSSException(message, e));
		}
	}

	/**
	 * Returns an unmodifiable list of all certificate tokens encapsulated in the
	 * signature
	 * 
	 * @see eu.europa.esig.dss.validation.AdvancedSignature#getCertificates()
	 */
	@Override
	public List<CertificateToken> getCertificates() {
		return getCertificateSource().getCertificates();
	}
	
	/**
	 * This method returns all validation data to be included into the signature
	 * @param validationContext {@link ValidationContext} contained all extracted data during the validation
	 * @return {@link ValidationDataForInclusion} all validation data to be included to the signature excluding duplicates and cross-certificates
	 */
	public ValidationDataForInclusion getValidationDataForInclusion(final ValidationContext validationContext) {
		Set<CertificateToken> certificatesForInclusion = getCertificatesForInclusion(validationContext);
		List<CRLToken> crlsForInclusion = getCRLsForInclusion(validationContext.getProcessedRevocations(), certificatesForInclusion);
		List<OCSPToken> ocspsForInclusion = getOCSPsForInclusion(validationContext.getProcessedRevocations(), certificatesForInclusion);
		
		return new ValidationDataForInclusion(certificatesForInclusion, crlsForInclusion, ocspsForInclusion);
	}

	/**
	 * This method returns all certificates used during the validation process. If a certificate's public key is
	 * already present within the signature then it is ignored.
	 *
	 * @param validationContext
	 *            validation context containing all information about the validation process of the signing certificate
	 *            and time-stamps
	 * @return set of certificates which public keys not yet present within the signature
	 */
	private Set<CertificateToken> getCertificatesForInclusion(final ValidationContext validationContext) {
		final Set<CertificateToken> certificatesForInclusion = getCompleteCertificateSource().getAllCertificateTokens();

		// avoid adding of cross-certificates to the list
		final List<EntityIdentifier> publicKeys = getEntityIdentifierList(certificatesForInclusion);
		for (final CertificateToken certificateToken : validationContext.getProcessedCertificates()) {
			if (!publicKeys.contains(certificateToken.getEntityKey())) {
				certificatesForInclusion.add(certificateToken);
			} else {
				LOG.debug("Certificate Token with Id : [{}] has not been added for inclusion. "
						+ "The same public key is already present!", certificateToken.getDSSIdAsString());
			}
		}
		return certificatesForInclusion;
	}

	/**
	 * Returns a map between found certificate chains in signature and timestamps
	 * @param skipLastArchiveTimestamp - if chain for the last archive timestamp must not be included to the final map
	 * @return map between signature/timestamp instances and their certificate chains
	 */
	public Map<String, List<CertificateToken>> getCertificateMapWithinSignatureAndTimestamps(boolean skipLastArchiveTimestamp) {
		// We can have more than one chain in the signature : signing certificate, ocsp
		// responder, ...
		Map<String, List<CertificateToken>> certificateMap = new HashMap<>();
		
		// add signature certificates
		List<CertificateToken> certificatesSig = getCertificateSource().getCertificates();
		if (Utils.isCollectionNotEmpty(certificatesSig)) {
			certificateMap.put(CertificateSourceType.SIGNATURE.name(), certificatesSig);
		}
		
		// add timestamp certificates
		certificateMap.putAll(getTimestampSource().getCertificateMapWithinTimestamps(skipLastArchiveTimestamp));

		return certificateMap;
	}
	
	private List<EntityIdentifier> getEntityIdentifierList(Collection<CertificateToken> certificateTokens) {
		final List<EntityIdentifier> entityIdentifiers = new ArrayList<>();
		for (CertificateToken certificateToken : certificateTokens) {
			entityIdentifiers.add(certificateToken.getEntityKey());
		}
		return entityIdentifiers;
	}

	/**
	 * This method returns CRLs that will be included in the LT profile.
	 *
	 * @param processedRevocations
	 *            {@link RevocationToken} contains all the revocation data retrieved during the validation process
	 * @param certificatesToBeIncluded
	 *            {@link CertificateToken} contains all the certificate tokens to be included to the signature
	 * @return list of {@link CRLToken}s to be included to the signature
	 */
	private List<CRLToken> getCRLsForInclusion(
			final Set<RevocationToken<Revocation>> processedRevocations, 
			final Set<CertificateToken> certificatesToBeIncluded) {
		
		final List<CRLToken> crlTokens = new ArrayList<>();
		final List<TokenIdentifier> revocationIds = new ArrayList<>();
		
		for (final RevocationToken revocationToken : processedRevocations) {
			if (!revocationIds.contains(revocationToken.getDSSId()) && isAtLeastOneCertificateCovered(revocationToken, certificatesToBeIncluded)) {
				revocationIds.add(revocationToken.getDSSId());
				if (revocationToken instanceof CRLToken) {
					final CRLToken crlToken = (CRLToken) revocationToken;
					crlTokens.add(crlToken);
				}
			}
		}
		return crlTokens;
	}

	/**
	 * This method returns OCSPs that will be included in the LT profile.
	 *
	 * @param processedRevocations
	 *            {@link RevocationToken} contains all the revocation data retrieved during the validation process
	 * @param certificatesToBeIncluded
	 *            {@link CertificateToken} contains all the certificate tokens to be included to the signature
	 * @return list of {@link OCSPToken}s to be included to the signature
	 */
	private List<OCSPToken> getOCSPsForInclusion(
			final Set<RevocationToken<Revocation>> processedRevocations, 
			final Set<CertificateToken> certificatesToBeIncluded) {
		
		final List<OCSPToken> ocspTokens = new ArrayList<>();
		final List<TokenIdentifier> revocationIds = new ArrayList<>();
		
		for (final RevocationToken revocationToken : processedRevocations) {
			if (!revocationIds.contains(revocationToken.getDSSId()) && isAtLeastOneCertificateCovered(revocationToken, certificatesToBeIncluded)) {
				revocationIds.add(revocationToken.getDSSId());
				if (revocationToken instanceof OCSPToken) {
					final OCSPToken ocspToken = (OCSPToken) revocationToken;
					ocspTokens.add(ocspToken);
				}
			}
		}
		return ocspTokens;
	}
	
	/**
	 * The method allows to avoid adding of revocation data for certificates that had been removed from the inclusion
	 */
	private boolean isAtLeastOneCertificateCovered(RevocationToken revocationToken, 
			final Collection<CertificateToken> certificateTokens) {
		String relatedCertificateID = revocationToken.getRelatedCertificateID();
		if (Utils.isStringNotEmpty(relatedCertificateID)) {
			for (CertificateToken certificateToken : certificateTokens) {
				if (certificateToken.getDSSIdAsString().equals(relatedCertificateID)) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public void setMasterSignature(final AdvancedSignature masterSignature) {
		this.masterSignature = masterSignature;
	}

	@Override
	public AdvancedSignature getMasterSignature() {
		return masterSignature;
	}

	@Override
	public SignatureCryptographicVerification getSignatureCryptographicVerification() {
		if (signatureCryptographicVerification == null) {
			checkSignatureIntegrity();
		}
		return signatureCryptographicVerification;
	}

	public static class ValidationDataForInclusion {

		public final Set<CertificateToken> certificateTokens;
		public final List<CRLToken> crlTokens;
		public final List<OCSPToken> ocspTokens;

		public ValidationDataForInclusion(final Set<CertificateToken> certificateTokens, 
				final List<CRLToken> crlTokens, final List<OCSPToken> ocspTokens) {
			this.certificateTokens = certificateTokens;
			this.crlTokens = crlTokens;
			this.ocspTokens = ocspTokens;
		}
		
	}
	
	@Override
	public List<SignerRole> getSignerRoles() {
		List<SignerRole> signerRoles = new ArrayList<>();
		List<SignerRole> claimedSignerRoles = getClaimedSignerRoles();
		if (Utils.isCollectionNotEmpty(claimedSignerRoles)) {
			signerRoles.addAll(claimedSignerRoles);
		}
		List<SignerRole> certifiedSignerRoles = getCertifiedSignerRoles();
		if (Utils.isCollectionNotEmpty(certifiedSignerRoles)) {
			signerRoles.addAll(certifiedSignerRoles);
		}
		return signerRoles;
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
		checkSignatureIntegrity();
		signatureCryptographicVerification = getSignatureCryptographicVerification();
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
	 * @param validationContext
	 *            {@code ValidationContext} to which the timestamps must be added
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

	@Override
	public void validateStructure() {
	}

	@Override
	public String getStructureValidationResult() {
		return structureValidation;
	}

	@Override
	public SignaturePolicy getPolicyId() {
		return signaturePolicy;
	}
	
	@Override
	public void findSignatureScope(SignatureScopeFinder signatureScopeFinder) {
		signatureScopes = signatureScopeFinder.findSignatureScope(this);
	}

	@Override
	public List<SignatureScope> getSignatureScopes() {
		return signatureScopes;
	}
	
	@Override
	public List<TimestampToken> getContentTimestamps() {
		return getTimestampSource().getContentTimestamps();
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {
		return getTimestampSource().getSignatureTimestamps();
	}

	@Override
	public List<TimestampToken> getTimestampsX1() {
		return getTimestampSource().getTimestampsX1();
	}

	@Override
	public List<TimestampToken> getTimestampsX2() {
		return getTimestampSource().getTimestampsX2();
	}

	@Override
	public List<TimestampToken> getArchiveTimestamps() {
		return getTimestampSource().getArchiveTimestamps();
	}

	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		return getTimestampSource().getDocumentTimestamps();
	}
	
	@Override
	public List<TimestampToken> getAllTimestamps() {
		return getTimestampSource().getAllTimestamps();
	}

	@Override
	public void addExternalTimestamp(TimestampToken timestamp) {
		if (!timestamp.isProcessed()) {
			throw new DSSException("Timestamp token must be validated first !");
		}

		if (!timestamp.getTimeStampType().isArchivalTimestamp()) {
			throw new DSSException("Only archival timestamp is allowed !");
		}

		getTimestampSource().addExternalTimestamp(timestamp);
	}

	/* Defines the level T */
	public boolean hasTProfile() {
		return Utils.isCollectionNotEmpty(getSignatureTimestamps());
	}

	/* Defines the level LT */
	public boolean hasLTProfile() {
		Map<String, List<CertificateToken>> certificateChains = getCertificateMapWithinSignatureAndTimestamps(true);

		boolean emptyCRLs = getCompleteCRLSource().isEmpty();
		boolean emptyOCSPs = getCompleteOCSPSource().isEmpty();

		if (Utils.isMapEmpty(certificateChains) && (emptyCRLs || emptyOCSPs)) {
			return false;
		}

		if (!areAllCertChainsHaveRevocationData(certificateChains)) {
			return false;
		}

		if (areAllSelfSignedCertificates(certificateChains) && (emptyCRLs && emptyOCSPs)) {
			return false;
		}

		return true;
	}
	
	@Override
	public boolean areAllSelfSignedCertificates() {
		return areAllSelfSignedCertificates(getCertificateMapWithinSignatureAndTimestamps(false));
	}

	private boolean areAllSelfSignedCertificates(Map<String, List<CertificateToken>> certificateChains) {
		for (Entry<String, List<CertificateToken>> entryCertChain : certificateChains.entrySet()) {
			List<CertificateToken> chain = entryCertChain.getValue();
			if (Utils.collectionSize(chain) == 1) {
				CertificateToken certificateToken = chain.get(0);
				if (!certificateToken.isSelfSigned()) {
					return false;
				}
			} else {
				return false;
			}
		}
		return true;
	}

	private boolean areAllCertChainsHaveRevocationData(Map<String, List<CertificateToken>> certificateChains) {
		for (Entry<String, List<CertificateToken>> entryCertChain : certificateChains.entrySet()) {
			LOG.debug("Testing revocation data presence for certificates chain {}", entryCertChain.getKey());
			if (!areAllCertsHaveRevocationData(entryCertChain.getValue())) {
				LOG.debug("Revocation data missing in certificate chain {}", entryCertChain.getKey());
				return false;
			}
		}
		return true;
	}

	private boolean areAllCertsHaveRevocationData(List<CertificateToken> certificates) {
		// we reorder the certificate list, the order is not guaranteed
		Map<CertificateToken, List<CertificateToken>> orderedCerts = order(certificates);
		for (List<CertificateToken> chain : orderedCerts.values()) {
			for (CertificateToken certificateToken : chain) {
				if (!isRevocationRequired(certificateToken)) {
					// Skip this loop to avoid checking upper levels than trusted certificates
					// (cross certification)
					break;
				}
				CertificateToken issuerToken = certPool.getIssuer(certificateToken);
				if (issuerToken == null) {
					LOG.warn("Issuer not found for certificate {}", certificateToken.getDSSIdAsString());
					return false;
				}

				List<RevocationToken<Revocation>> revocationTokens = getCompleteOCSPSource().getRevocationTokens(certificateToken, issuerToken);
				if (Utils.isCollectionEmpty(revocationTokens)) {
					revocationTokens = getCompleteCRLSource().getRevocationTokens(certificateToken, issuerToken);
				}

				if (Utils.isCollectionEmpty(revocationTokens)) {
					return false;
				}
			}
		}
		return true;
	}

	private Map<CertificateToken, List<CertificateToken>> order(List<CertificateToken> certificates) {
		CertificateReorderer reorderer = new CertificateReorderer(certificates);
		return reorderer.getOrderedCertificateChains();
	}

	private boolean isRevocationRequired(CertificateToken certificateToken) {
		if (certPool.isTrusted(certificateToken) || certificateToken.isSelfSigned()) {
			return false;
		}

		return !DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certificateToken);
	}

	/* Defines the level LTA */
	public boolean hasLTAProfile() {
		return Utils.isCollectionNotEmpty(getArchiveTimestamps());
	}
	
	@Override
	public boolean isDocHashOnlyValidation() {
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			for (DSSDocument dssDocument : detachedContents) {
				if (!(dssDocument instanceof DigestDocument)) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	@Override
	public boolean isHashOnlyValidation() {
		// TODO: not implemented yet
		return false;
	}
	
	@Override
	public byte[] getMessageDigestValue() {
		// Not applicable by default (CAdES/PAdES only)
		return null;
	}
	
	@Override
	public Set<CertificateIdentifier> getSignerInformationStoreInfos() {
		// Not applicable by default (CAdES/PAdES only)
		return null;
	}
	
	@Override
	public PdfRevision getPdfRevision() {
		// Not applicable by default (PDF only)
		return null;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || !(obj instanceof DefaultAdvancedSignature)) {
			return false;
		}
		DefaultAdvancedSignature das = (DefaultAdvancedSignature) obj;
		return getDSSId().equals(das.getDSSId());
	}

	@Override
	public int hashCode() {
		return getDSSId().hashCode();
	}

}
