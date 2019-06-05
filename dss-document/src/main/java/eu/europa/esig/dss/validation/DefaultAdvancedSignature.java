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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.CertificateReorderer;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.SignatureIdentifier;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.TokenIdentifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.SignatureTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.RevocationRef;
import eu.europa.esig.dss.x509.revocation.RevocationSourceType;
import eu.europa.esig.dss.x509.revocation.crl.CRLBinaryIdentifier;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.crl.ListCRLSource;
import eu.europa.esig.dss.x509.revocation.crl.SignatureCRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.ListOCSPSource;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponseIdentifier;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;

public abstract class DefaultAdvancedSignature implements AdvancedSignature {

	private static final long serialVersionUID = 6452189007886779360L;

	private static final Logger LOG = LoggerFactory.getLogger(DefaultAdvancedSignature.class);

	/**
	 * This is the reference to the global (external) pool of certificates. All encapsulated certificates in the signature are added to this pool. See
	 * {@link eu.europa.esig.dss.x509.CertificatePool}
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
	protected List<DSSDocument> containerContents;
	
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

	// Cached {@code SignatureCRLSource}
	protected SignatureCRLSource offlineCRLSource;

	// Cached {@code SignatureOCSPSource}
	protected SignatureOCSPSource offlineOCSPSource;

	// Cached {@code SignatureTimestampSource}
	protected SignatureTimestampSource signatureTimestampSource;

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
	public List<CertificateRef> getOrphanCertificateRefs() {
		return getCertificateSource().getOrphanCertificateRefs();
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
		return "S-" + getDSSId().asXmlId();
	}

	@Override
    public List<DSSDocument> getManifestedDocuments() {
    	List<DSSDocument> foundManifestedDocuments = new ArrayList<DSSDocument>();
    	if (Utils.isCollectionEmpty(manifestFiles) || 
    			Utils.isCollectionEmpty(containerContents)) {
    		return foundManifestedDocuments;
    	}
    	for (ManifestFile manifestFile : manifestFiles) {
    		if (manifestFile.getSignatureFilename().equals(signatureFilename)) {
    			for (DSSDocument document : containerContents) {
    				if (manifestFile.getEntries().contains(document.getName())) {
    					foundManifestedDocuments.add(document);
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
		certificateVerifier.setSignatureCRLSource(new ListCRLSource(getCRLSource()));
		certificateVerifier.setSignatureOCSPSource(new ListOCSPSource(getOCSPSource()));
		validationContext.initialize(certificateVerifier);

		final List<CertificateToken> certificates = getCertificates();
		for (final CertificateToken certificate : certificates) {
			validationContext.addCertificateTokenForVerification(certificate);
		}
		prepareTimestamps(validationContext);
		validationContext.validate();

		checkTimestamp(certificateVerifier, validationContext);
		checkAllRevocationDataPresent(certificateVerifier, validationContext);
		checkAllTimestampCoveredByRevocationData(certificateVerifier, validationContext);
		checkAllCertificateNotRevoked(certificateVerifier, validationContext);

		return validationContext;
	}

	private void checkAllCertificateNotRevoked(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		if (!validationContext.isAllCertificateValid()) {
			String message = "Revoked certificate detected";
			if (certificateVerifier.isExceptionOnRevokedCertificate()) {
				throw new DSSException(message);
			} else {
				LOG.warn(message);
			}
		}
	}

	private void checkAllTimestampCoveredByRevocationData(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		if (!validationContext.isAllPOECoveredByRevocationData()) {
			String message = "A POE is not covered by an usable revocation data";
			if (certificateVerifier.isExceptionOnUncoveredPOE()) {
				throw new DSSException(message);
			} else {
				LOG.warn(message);
			}
		}
	}

	private void checkAllRevocationDataPresent(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		if (!validationContext.isAllRequiredRevocationDataPresent()) {
			String message = "Revocation data is missing";
			if (certificateVerifier.isExceptionOnMissingRevocationData()) {
				throw new DSSException(message);
			} else {
				LOG.warn(message);
			}
		}
	}

	private void checkTimestamp(final CertificateVerifier certificateVerifier, final ValidationContext validationContext) {
		if (!validationContext.isAllTimestampValid()) {
			String message = "Broken timestamp detected";
			if (certificateVerifier.isExceptionOnInvalidTimestamp()) {
				throw new DSSException(message);
			} else {
				LOG.warn(message);
			}
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
	 * Returns a set of {@link CertificateToken}s found in the {@link SignatureTimestampSource}
	 * @return set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getTimestampSourceCertificates() {
		return getTimestampSource().getCertificates();
	}

	/**
	 * This method returns all certificates used during the validation process. If a certificate is already present
	 * within the signature then it is ignored.
	 *
	 * @param validationContext
	 *            validation context containing all information about the validation process of the signing certificate
	 *            and time-stamps
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
	
	public List<String> getCertificatesWithinSignatureAndTimestampIds() {
		List<String> certificateIds = new ArrayList<String>();
		for (CertificateToken certificateToken : getCertificatesWithinSignatureAndTimestamps()) {
			certificateIds.add(certificateToken.getDSSIdAsString());
		}
		return certificateIds;
	}

	public List<CertificateToken> getCertificatesWithinSignatureAndTimestamps() {
		List<CertificateToken> certs = new ArrayList<CertificateToken>();
		Set<CertificateToken> certificatesWithiTimestamps = getTimestampSourceCertificates();
		for (CertificateToken token : certificatesWithiTimestamps) {
			if (!certs.contains(token)) {
				certs.add(token);
			}
		}
		return certs;
	}

	public Map<String, List<CertificateToken>> getCertificatesWithinSignatureAndTimestamps(boolean skipLastArchiveTimestamp) {
		// We can have more than one chain in the signature : signing certificate, ocsp
		// responder, ...
		Map<String, List<CertificateToken>> certificateMap = new HashMap<String, List<CertificateToken>>();
		
		List<CertificateToken> certificatesSig = getCertificateSource().getCertificates();
		
		if (Utils.isCollectionNotEmpty(certificatesSig)) {
			certificateMap.put(CertificateSourceType.SIGNATURE.name(), certificatesSig);
		}
		certificateMap.putAll(getTimestampSource().getCertificateMapWithinTimestamps(skipLastArchiveTimestamp));

		return certificateMap;
	}

	/**
	 * This method returns revocation values (ocsp and crl) that will be included in the LT profile.
	 *
	 * @param validationContext
	 *            {@code ValidationContext} contains all the revocation data retrieved during the validation process.
	 * @return {@code RevocationDataForInclusion}
	 */
	public RevocationDataForInclusion getRevocationDataForInclusion(final ValidationContext validationContext) {
		// TODO: to be checked: there can be also CRL and OCSP in TimestampToken CMS data
		final Set<RevocationToken> revocationTokens = validationContext.getProcessedRevocations();
		final List<CRLToken> crlTokens = new ArrayList<CRLToken>();
		final List<OCSPToken> ocspTokens = new ArrayList<OCSPToken>();
		final List<TokenIdentifier> revocationIds = new ArrayList<TokenIdentifier>(); // revocation equals : TokenId + certId + date
		for (final RevocationToken revocationToken : revocationTokens) {
			if (!revocationIds.contains(revocationToken.getDSSId())) {
				revocationIds.add(revocationToken.getDSSId());
				if (revocationToken instanceof CRLToken) {
					final CRLToken crlToken = (CRLToken) revocationToken;
					crlTokens.add(crlToken);
				} else if (revocationToken instanceof OCSPToken) {
					final OCSPToken ocspToken = (OCSPToken) revocationToken;
					ocspTokens.add(ocspToken);
				} else {
					throw new DSSException("Unknown type for revocationToken: " + revocationToken.getClass().getName());
				}
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

	@Override
	public SignatureCryptographicVerification getSignatureCryptographicVerification() {
		if (signatureCryptographicVerification == null) {
			checkSignatureIntegrity();
		}
		return signatureCryptographicVerification;
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
	
	protected List<TimestampedReference> getContentTimestampReferences() {
		final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (SignatureScope signatureScope : signatureScopes) {
				addReference(references, new TimestampedReference(signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));
			}
		}
		return references;
	}

	protected List<TimestampedReference> getSignatureTimestampReferences() {
		final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		addReferences(references, getContentTimestampReferences());
		addReference(references, new TimestampedReference(getId(), TimestampedObjectType.SIGNATURE));
		addReferences(references, getSigningCertificateTimestampReferences());
		return references;
	}

	protected List<TimestampedReference> getSigningCertificateTimestampReferences() {
		final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		List<CertificateToken> signingCertificates = getCertificateSource().getSigningCertificates();
		for (CertificateToken certificateToken : signingCertificates) {
			addReference(references, new TimestampedReference(certificateToken.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		return references;
	}

	protected void addReferencesForPreviousTimestamps(List<TimestampedReference> references, List<TimestampToken> timestampedTimestamps) {
		for (final TimestampToken timestampToken : timestampedTimestamps) {
			addReference(references, new TimestampedReference(timestampToken.getDSSIdAsString(), TimestampedObjectType.TIMESTAMP));
			addEncapsulatedCertificatesFromTimestamp(references, timestampToken);
		}
	}
	
	protected void addEncapsulatedCertificatesFromTimestamp(List<TimestampedReference> references, TimestampToken timestampedTimestamp) {
		List<CertificateToken> certificates = timestampedTimestamp.getCertificates();
		for (final CertificateToken certificate : certificates) {
			addReference(references, new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
	}

	protected void addReferencesForCertificates(List<TimestampedReference> references) {
		List<CertificateToken> certValues = getCertificateSource().getCertificateValues();
		for (CertificateToken certificate : certValues) {
			addReference(references, new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		List<CertificateToken> completeCertValues = getCertificateSource().getCompleteCertificates();
		for (CertificateToken certificate : completeCertValues) {
			addReference(references, new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
	}
	
	/**
	 * Creates a list of {@link TimestampedReference}s for the provided {@code certificateTokens}
	 * @param certificateTokens list of {@link CertificateToken}s to create timestamped references for
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getTimestampedReferencesFromCertificates(List<CertificateToken> certificateTokens) {
		List<TimestampedReference> timestampedReferences = new ArrayList<TimestampedReference>();
		for (final CertificateToken certificateToken : certificateTokens) {
			timestampedReferences.add(new TimestampedReference(certificateToken.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		return timestampedReferences;
	}

	/**
	 * This method adds references to retrieved revocation data.
	 * 
	 * @param references
	 */
	protected void addReferencesFromRevocationData(List<TimestampedReference> references) {
		List<RevocationToken> completeRevocationTokens = getCompleteRevocationTokens();
		for (RevocationToken revocationToken : completeRevocationTokens) {
			addReference(references, new TimestampedReference(revocationToken.getDSSIdAsString(), TimestampedObjectType.REVOCATION));
		}
	}
	
	/**
	 * Adds {@code referenceToAdd} to {@code referenceList} without duplicates
	 * @param referenceList - list of {@link TimestampedReference}s to be extended
	 * @param referenceToAdd - {@link TimestampedReference} to be added
	 */
	protected void addReference(List<TimestampedReference> referenceList, TimestampedReference referenceToAdd) {
		addReferences(referenceList, Arrays.asList(referenceToAdd));
	}
	/**
	 * Adds {@code referencesToAdd} to {@code referenceList} without duplicates
	 * @param referenceList - list of {@link TimestampedReference}s to be extended
	 * @param referencesToAdd - {@link TimestampedReference}s to be added
	 */
	protected void addReferences(List<TimestampedReference> referenceList, List<TimestampedReference> referencesToAdd) {
		for (TimestampedReference reference : referencesToAdd) {
			if (!referenceList.contains(reference)) {
				referenceList.add(reference);
			}
		}
	}

	@Override
	public SignaturePolicy getPolicyId() {
		return signaturePolicy;
	}

	@Override
	public void checkSignaturePolicy(SignaturePolicyProvider signaturePolicyDetector) {
	}
	
	@Override
	public void populateCRLTokenLists(SignatureCRLSource signatureCRLSource) {
		offlineCRLSource.populateCRLRevocationValues(signatureCRLSource);
	}
	
	@Override
	public void populateOCSPTokenLists(SignatureOCSPSource signatureOCSPSource) {
		offlineOCSPSource.populateOCSPRevocationTokenLists(signatureOCSPSource);
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
	public SignatureTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			initializeSignatureTimestampSource();
		}
		return signatureTimestampSource;
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
	
	/**
	 * This method initializes the {@link SignatureTimestampSource}
	 */
	protected abstract void initializeSignatureTimestampSource();

	@Override
	public void addExternalTimestamp(TimestampToken timestamp) {
		if (!timestamp.isProcessed()) {
			throw new DSSException("Timestamp token must be validated first !");
		}

		if (!TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getTimeStampType())) {
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
		Map<String, List<CertificateToken>> certificateChains = getCertificatesWithinSignatureAndTimestamps(true);
		
		boolean emptyOCSPs = getOCSPSource().isEmpty();
		boolean emptyCRLs = getCRLSource().isEmpty();

		if (Utils.isMapEmpty(certificateChains) && (emptyOCSPs || emptyCRLs)) {
			return false;
		}

		if (!isAllCertChainsHaveRevocationData(certificateChains)) {
			return false;
		}

		if (isAllSelfSignedCertificates(certificateChains) && (emptyOCSPs && emptyCRLs)) {
			return false;
		}

		return true;
	}

	private boolean isAllSelfSignedCertificates(Map<String, List<CertificateToken>> certificateChains) {
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

	private boolean isAllCertChainsHaveRevocationData(Map<String, List<CertificateToken>> certificateChains) {
		CertificateStatusVerifier certificateStatusVerifier = new OCSPAndCRLCertificateVerifier(getCRLSource(), getOCSPSource(), certPool);

		for (Entry<String, List<CertificateToken>> entryCertChain : certificateChains.entrySet()) {
			LOG.debug("Testing revocation data presence for certificates chain {}", entryCertChain.getKey());
			if (!isAllCertsHaveRevocationData(certificateStatusVerifier, entryCertChain.getValue())) {
				LOG.debug("Revocation data missing in certificate chain {}", entryCertChain.getKey());
				return false;
			}
		}
		return true;
	}

	private boolean isAllCertsHaveRevocationData(CertificateStatusVerifier certificateStatusVerifier, List<CertificateToken> certificates) {
		// we reorder the certificate list, the order is not guaranteed
		Map<CertificateToken, List<CertificateToken>> orderedCerts = order(certificates);
		for (List<CertificateToken> chain : orderedCerts.values()) {
			for (CertificateToken certificateToken : chain) {
				if (!isRevocationRequired(certificateToken)) {
					// Skip this loop to avoid checking upper levels than trusted certificates
					// (cross certification)
					break;
				}
				RevocationToken revocationData = certificateStatusVerifier.check(certificateToken);
				if (revocationData == null) {
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
	public Set<RevocationToken> getAllRevocationTokens() {
		Set<RevocationToken> allRevocations = new HashSet<RevocationToken>();
		allRevocations.addAll(getCRLSource().getAllCRLTokens());
		allRevocations.addAll(getOCSPSource().getAllOCSPTokens());
		return allRevocations;
	}

	@Override
	public List<RevocationToken> getRevocationValuesTokens() {
		List<RevocationToken> revocationTokens = new ArrayList<RevocationToken>();
		revocationTokens.addAll(getCRLSource().getRevocationValuesTokens());
		revocationTokens.addAll(getOCSPSource().getRevocationValuesTokens());
		return revocationTokens;
	}

	@Override
	public List<RevocationToken> getAttributeRevocationValuesTokens() {
		List<RevocationToken> revocationTokens = new ArrayList<RevocationToken>();
		revocationTokens.addAll(getCRLSource().getAttributeRevocationValuesTokens());
		revocationTokens.addAll(getOCSPSource().getAttributeRevocationValuesTokens());
		return revocationTokens;
	}

	@Override
	public List<RevocationToken> getTimestampRevocationValuesTokens() {
		List<RevocationToken> revocationTokens = new ArrayList<RevocationToken>();
		revocationTokens.addAll(getCRLSource().getTimestampRevocationValuesTokens());
		revocationTokens.addAll(getOCSPSource().getTimestampRevocationValuesTokens());
		return revocationTokens;
	}

	@Override
	public List<RevocationToken> getDSSDictionaryRevocationTokens() {
		List<RevocationToken> revocationTokens = new ArrayList<RevocationToken>();
		revocationTokens.addAll(getCRLSource().getDSSDictionaryTokens());
		revocationTokens.addAll(getOCSPSource().getDSSDictionaryTokens());
		return revocationTokens;
	}

	@Override
	public List<RevocationToken> getVRIDictionaryRevocationTokens() {
		List<RevocationToken> revocationTokens = new ArrayList<RevocationToken>();
		revocationTokens.addAll(getCRLSource().getVRIDictionaryTokens());
		revocationTokens.addAll(getOCSPSource().getVRIDictionaryTokens());
		return revocationTokens;
	}
	
	@Override
	public List<CRLRef> getCompleteRevocationCRLReferences() {
		return getCRLSource().getCompleteRevocationRefs();
	}

	@Override
	public List<CRLRef> getAttributeRevocationCRLReferences() {
		return getCRLSource().getAttributeRevocationRefs();
	}
	
	@Override
	public List<CRLRef> getTimestampRevocationCRLReferences() {
		return getCRLSource().getTimestampRevocationRefs();
	}
	
	@Override
	public List<OCSPRef> getCompleteRevocationOCSPReferences() {
		return getOCSPSource().getCompleteRevocationRefs();
	}

	@Override
	public List<OCSPRef> getAttributeRevocationOCSPReferences() {
		return getOCSPSource().getAttributeRevocationRefs();
	}

	@Override
	public List<OCSPRef> getTimestampRevocationOCSPReferences() {
		return getOCSPSource().getTimestampRevocationRefs();
	}
	
	@Override
	public List<RevocationRef> getAllFoundRevocationRefs() {
		List<RevocationRef> revocationRefs = new ArrayList<RevocationRef>();
		revocationRefs.addAll(getCompleteRevocationCRLReferences());
		revocationRefs.addAll(getAttributeRevocationCRLReferences());
		revocationRefs.addAll(getTimestampRevocationCRLReferences());
		revocationRefs.addAll(getCompleteRevocationOCSPReferences());
		revocationRefs.addAll(getAttributeRevocationOCSPReferences());
		revocationRefs.addAll(getTimestampRevocationOCSPReferences());
		return revocationRefs;
	}
	
	@Override
	public List<RevocationRef> getOrphanRevocationRefs() {
		List<RevocationRef> orphanRevocationRefs = new ArrayList<RevocationRef>();
		orphanRevocationRefs.addAll(getCRLSource().getOrphanCrlRefs());
		orphanRevocationRefs.addAll(getOCSPSource().getOrphanOCSPRefs());
		return orphanRevocationRefs;
	}

	@Override
	public List<RevocationToken> getCompleteRevocationTokens() {
		List<RevocationToken> revocations = new ArrayList<RevocationToken>();
		revocations.addAll(getCRLSource().findTokensFromRefs(getCRLSource().getCompleteRevocationRefs()));
		revocations.addAll(getOCSPSource().findTokensFromRefs(getOCSPSource().getCompleteRevocationRefs()));
		return revocations;
	}

	@Override
	public List<RevocationToken> getAttributeRevocationTokens() {
		List<RevocationToken> revocations = new ArrayList<RevocationToken>();
		revocations.addAll(getCRLSource().findTokensFromRefs(getCRLSource().getAttributeRevocationRefs()));
		revocations.addAll(getOCSPSource().findTokensFromRefs(getOCSPSource().getAttributeRevocationRefs()));
		return revocations;
	}
	
	@Override
	public List<RevocationRef> findRefsForRevocationToken(RevocationToken revocationToken) {
		List<RevocationRef> revocationRefs = new ArrayList<RevocationRef>();
		if (RevocationSourceType.CRL.equals(revocationToken.getRevocationSourceType())) {
			revocationRefs.addAll(getCRLSource().findRefsForRevocationToken((CRLToken)revocationToken));
		} else {
			revocationRefs.addAll(getOCSPSource().findRefsForRevocationToken((OCSPToken)revocationToken));
		}
		return revocationRefs;
	}
	
	@Override
	public List<RevocationRef> findRefsForRevocationIdentifier(EncapsulatedRevocationTokenIdentifier revocationIdentifier) {
		List<RevocationRef> revocationRefs = new ArrayList<RevocationRef>();
		if (revocationIdentifier instanceof CRLBinaryIdentifier) {
			revocationRefs.addAll(getCRLSource().getReferencesForCRLIdentifier((CRLBinaryIdentifier) revocationIdentifier));
		} else {
			revocationRefs.addAll(getOCSPSource().getReferencesForOCSPIdentifier((OCSPResponseIdentifier) revocationIdentifier));
		}
		return revocationRefs;
	}
	
	@Override
	public List<EncapsulatedRevocationTokenIdentifier> getAllFoundRevocationIdentifiers() {
		List<EncapsulatedRevocationTokenIdentifier> allFoundRevocationTokens = new ArrayList<EncapsulatedRevocationTokenIdentifier>();
		allFoundRevocationTokens.addAll(getCRLSource().getContainedX509CRLs());
		allFoundRevocationTokens.addAll(getOCSPSource().getOCSPResponsesList());
		return allFoundRevocationTokens;
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
	public String getSignatureFieldName() {
		// Not applicable by default (PDF only)
		return null;
	}

	@Override
	public String getSignerName() {
		// Not applicable by default (PDF only)
		return null;
	}

	@Override
	public String getFilter() {
		// Not applicable by default (PDF only)
		return null;
	}

	@Override
	public String getSubFilter() {
		// Not applicable by default (PDF only)
		return null;
	}

	@Override
	public String getContactInfo() {
		// Not applicable by default (PDF only)
		return null;
	}

	@Override
	public String getReason() {
		// Not applicable by default (PDF only)
		return null;
	}

	@Override
	public int[] getSignatureByteRange() {
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
