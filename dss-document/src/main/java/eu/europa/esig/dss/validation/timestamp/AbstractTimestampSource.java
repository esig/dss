package eu.europa.esig.dss.validation.timestamp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.EncapsulatedCertificateTokenIdentifier;
import eu.europa.esig.dss.EncapsulatedTokenIdentifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.SignatureScope;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.x509.ArchiveTimestampType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.CRLBinaryIdentifier;
import eu.europa.esig.dss.x509.revocation.crl.ListCRLSource;
import eu.europa.esig.dss.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.ListOCSPSource;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponseIdentifier;
import eu.europa.esig.dss.x509.revocation.ocsp.OfflineOCSPSource;

/**
 * Contains a set of {@link TimestampToken}s found in a {@link DefaultAdvancedSignature} object
 */
public abstract class AbstractTimestampSource<SignatureAttribute extends ISignatureAttribute> implements SignatureTimestampSource {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractTimestampSource.class);
	
	protected SignatureCertificateSource certificateSource;
	protected ListCRLSource crlSource;
	protected ListOCSPSource ocspSource;
	
	protected String signatureId;
	protected List<SignatureScope> signatureScopes;
	protected CertificatePool certificatePool;

	// Enclosed content timestamps.
	protected List<TimestampToken> contentTimestamps;

	// Enclosed signature timestamps.
	protected List<TimestampToken> signatureTimestamps;

	// Enclosed SignAndRefs timestamps.
	protected List<TimestampToken> sigAndRefsTimestamps;

	// Enclosed RefsOnly timestamps.
	protected List<TimestampToken> refsOnlyTimestamps;

	// This variable contains the list of enclosed archive signature timestamps.
	protected List<TimestampToken> archiveTimestamps;
	
	public void setCertificateSource(SignatureCertificateSource certificateSource) {
		this.certificateSource = certificateSource;
	}
	
	public void setCRLSource(OfflineCRLSource crlSource) {
		this.crlSource = new ListCRLSource(crlSource);
	}
	
	public void setOCSPSource(OfflineOCSPSource ocspSource) {
		this.ocspSource = new ListOCSPSource(ocspSource);
	}
	
	public void setSignatureDSSId(String signatureDSSId) {
		this.signatureId = signatureDSSId;
	}
	
	public void setSignatureScopes(List<SignatureScope> signatureScopes) {
		this.signatureScopes = signatureScopes;
	}
	
	protected void setCertificatePool(CertificatePool certificatePool) {
		this.certificatePool = certificatePool;
	}
	
	@Override
	public List<TimestampToken> getContentTimestamps() {
		if (contentTimestamps == null) {
			createAndValidate();
		}
		return contentTimestamps;
	}
	
	@Override
	public List<TimestampToken> getSignatureTimestamps() {
		if (signatureTimestamps == null) {
			createAndValidate();
		}
		return signatureTimestamps;
	}
	
	@Override
	public List<TimestampToken> getTimestampsX1() {
		if (sigAndRefsTimestamps == null) {
			createAndValidate();
		}
		return sigAndRefsTimestamps;
	}
	
	@Override
	public List<TimestampToken> getTimestampsX2() {
		if (refsOnlyTimestamps == null) {
			createAndValidate();
		}
		return refsOnlyTimestamps;
	}
	
	@Override
	public List<TimestampToken> getArchiveTimestamps() {
		if (archiveTimestamps == null) {
			createAndValidate();
		}
		return archiveTimestamps;
	}
	
	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		/** Applicable only for PAdES */
		return Collections.emptyList();
	}
	
	@Override
	public List<TimestampToken> getAllTimestamps() {
		List<TimestampToken> timestampTokens = new ArrayList<TimestampToken>();
		timestampTokens.addAll(getContentTimestamps());
		timestampTokens.addAll(getSignatureTimestamps());
		timestampTokens.addAll(getTimestampsX1());
		timestampTokens.addAll(getTimestampsX2());
		timestampTokens.addAll(getArchiveTimestamps());
		return timestampTokens;
	}
	
	/**
	 * Creates and validates all timestamps
	 * Must be called only once
	 */
	protected void createAndValidate() {
		makeTimestampTokens();
		validateTimestamps();
	}
	
	@Override
	public void addExternalTimestamp(TimestampToken timestamp) {
		// if timestamp tokens not created yet
		if (archiveTimestamps == null) {
			createAndValidate();;
		}
		switch (timestamp.getTimeStampType()) {
			case CONTENT_TIMESTAMP:
			case ALL_DATA_OBJECTS_TIMESTAMP:
			case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
				contentTimestamps.add(timestamp);
				break;
			case SIGNATURE_TIMESTAMP:
				signatureTimestamps.add(timestamp);
				break;
			case VALIDATION_DATA_REFSONLY_TIMESTAMP:
				refsOnlyTimestamps.add(timestamp);
				break;
			case VALIDATION_DATA_TIMESTAMP:
				sigAndRefsTimestamps.add(timestamp);
				break;
			case ARCHIVE_TIMESTAMP:
				archiveTimestamps.add(timestamp);
				break;
			default:
				LOG.warn("The signature timestamp source does not support timestamp tokens with type [{}]. "
						+ "The TimestampToken was not added.", timestamp.getTimeStampType().name());
				break;
		}
	}
	
	/**
	 * Populates all the lists by data found into the signature
	 */
	protected void makeTimestampTokens() {
		
		contentTimestamps = new ArrayList<TimestampToken>();
		signatureTimestamps = new ArrayList<TimestampToken>();
		sigAndRefsTimestamps = new ArrayList<TimestampToken>();
		refsOnlyTimestamps = new ArrayList<TimestampToken>();
		archiveTimestamps = new ArrayList<TimestampToken>();
		
		final SignatureProperties<SignatureAttribute> signedSignatureProperties = getSignedSignatureProperties();
		
		final List<SignatureAttribute> signedAttributes = signedSignatureProperties.getAttributes();
		for (SignatureAttribute signedAttribute : signedAttributes) {
			
			TimestampToken timestampToken;
			
			if (isContentTimestamp(signedAttribute)) {
				timestampToken = makeTimestampToken(signedAttribute, TimestampType.CONTENT_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(getAllContentTimestampReferences());
				
			} else if (isAllDataObjectsTimestamp(signedAttribute)) {
				timestampToken = makeTimestampToken(signedAttribute, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(getAllContentTimestampReferences());
				
			} else if (isIndividualDataObjectsTimestamp(signedAttribute)) {
				timestampToken = makeTimestampToken(signedAttribute, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				List<TimestampInclude> timestampIncludes = timestampToken.getTimestampIncludes();
				timestampToken.setTimestampedReferences(getIndividualContentTimestampedReferences(timestampIncludes));
				
			} else {
				continue;
				
			}
			contentTimestamps.add(timestampToken);
		}
		
		
		final SignatureProperties<SignatureAttribute> unsignedSignatureProperties = getUnsignedSignatureProperties();
		if (!unsignedSignatureProperties.isExist()) {
			// timestamp tokens cannot be created if signature does not contain "unsigned-signature-properties" element
			return;
		}
		
		final List<TimestampToken> timestamps = new ArrayList<TimestampToken>();
		final List<TimestampedReference> encapsulatedReferences = new ArrayList<TimestampedReference>();
		
		final List<SignatureAttribute> unsignedAttributes = unsignedSignatureProperties.getAttributes();
		for (SignatureAttribute unsignedAttribute : unsignedAttributes) {
			
			TimestampToken timestampToken;
			
			if (isSignatureTimestamp(unsignedAttribute)) {
				timestampToken = makeTimestampToken(unsignedAttribute, TimestampType.SIGNATURE_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(getSignatureTimestampReferences());
				signatureTimestamps.add(timestampToken);
				
			} else if (isCompleteCertificateRef(unsignedAttribute)) {
				encapsulatedReferences.addAll(getTimestampedCertificateRefs(unsignedAttribute));
				continue;
				
			} else if (isAttributeCertificateRef(unsignedAttribute)) {
				encapsulatedReferences.addAll(getTimestampedCertificateRefs(unsignedAttribute));
				continue;
				
			} else if (isCompleteRevocationRef(unsignedAttribute)) {
				encapsulatedReferences.addAll(getTimestampedRevocationRefs(unsignedAttribute));
				continue;
				
			} else if (isAttributeRevocationRef(unsignedAttribute)) {
				encapsulatedReferences.addAll(getTimestampedRevocationRefs(unsignedAttribute));
				continue;
				
			} else if (isRefsOnlyTimestamp(unsignedAttribute)) {
				timestampToken = makeTimestampToken(unsignedAttribute, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(encapsulatedReferences);
				refsOnlyTimestamps.add(timestampToken);
				
			} else if (isSigAndRefsTimestamp(unsignedAttribute)) {
				timestampToken = makeTimestampToken(unsignedAttribute, TimestampType.VALIDATION_DATA_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
				addReferencesForPreviousTimestamps(references, filterSignatureTimestamps(timestamps));
				addReferences(references, encapsulatedReferences);
				timestampToken.setTimestampedReferences(references);
				sigAndRefsTimestamps.add(timestampToken);
				
			} else if (isCertificateValues(unsignedAttribute)) {
				encapsulatedReferences.addAll(getTimestampedCertificateValues(unsignedAttribute));
				continue;
				
			} else if (isRevocationValues(unsignedAttribute)) {
				encapsulatedReferences.addAll(getTimestampedRevocationValues(unsignedAttribute));
				continue;
				
			} else if (isArchiveTimestamp(unsignedAttribute)) {
				timestampToken = makeTimestampToken(unsignedAttribute, TimestampType.ARCHIVE_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setArchiveTimestampType(getArchiveTimestampType(unsignedAttribute));
				final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
				addReferencesForPreviousTimestamps(references, timestamps);
				addReferences(references, encapsulatedReferences);
				timestampToken.setTimestampedReferences(references);
				archiveTimestamps.add(timestampToken);
				
			} else if (isTimeStampValidationData(unsignedAttribute)) {
				encapsulatedReferences.addAll(getTimestampValidationData(unsignedAttribute));
				continue;
				
			} else {
				LOG.warn("The unsigned attribute with name [{}] is not supported", unsignedAttribute.toString());
				continue;
			}
			
			timestamps.add(timestampToken);
			
		}
		
	}
	
	/**
	 * Returns the 'signed-signature-properties' element of the signature
	 * @return {@link SignatureProperties}
	 */
	protected abstract SignatureProperties<SignatureAttribute> getSignedSignatureProperties();
	
	/**
	 * Returns the 'unsigned-signature-properties' element of the signature
	 * @return {@link SignatureProperties}
	 */
	protected abstract SignatureProperties<SignatureAttribute> getUnsignedSignatureProperties();

	/**
	 * Determines if the given {@code signedAttribute} is an instance of "content-timestamp" element
	 * NOTE: Applicable only for CAdES
	 * @param signedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Data Objects Timestamp, FALSE otherwise
	 */
	protected abstract boolean isContentTimestamp(SignatureAttribute signedAttribute);
	
	/**
	 * Determines if the given {@code signedAttribute} is an instance of "data-objects-timestamp" element
	 * NOTE: Applicable only for XAdES
	 * @param signedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Data Objects Timestamp, FALSE otherwise
	 */
	protected abstract boolean isAllDataObjectsTimestamp(SignatureAttribute signedAttribute);
	
	/**
	 * Determines if the given {@code signedAttribute} is an instance of "individual-data-objects-timestamp" element
	 * NOTE: Applicable only for XAdES
	 * @param signedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Data Objects Timestamp, FALSE otherwise
	 */
	protected abstract boolean isIndividualDataObjectsTimestamp(SignatureAttribute signedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "signature-timestamp" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Signature Timestamp, FALSE otherwise
	 */
	protected abstract boolean isSignatureTimestamp(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "complete-certificate-ref" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Complete Certificate Ref, FALSE otherwise
	 */
	protected abstract boolean isCompleteCertificateRef(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "attribute-certificate-ref" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is an Attribute Certificate Ref, FALSE otherwise
	 */
	protected abstract boolean isAttributeCertificateRef(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "complete-revocation-ref" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Complete Revocation Ref, FALSE otherwise
	 */
	protected abstract boolean isCompleteRevocationRef(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "attribute-revocation-ref" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is an Attribute Revocation Ref, FALSE otherwise
	 */
	protected abstract boolean isAttributeRevocationRef(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "refs-only-timestamp" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Refs Only TimeStamp, FALSE otherwise
	 */
	protected abstract boolean isRefsOnlyTimestamp(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "sig-and-refs-timestamp" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Sig And Refs TimeStamp, FALSE otherwise
	 */
	protected abstract boolean isSigAndRefsTimestamp(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "certificate-values" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Certificate Values, FALSE otherwise
	 */
	protected abstract boolean isCertificateValues(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "revocation-values" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a Revocation Values, FALSE otherwise
	 */
	protected abstract boolean isRevocationValues(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "archive-timestamp" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is an Archive TimeStamp, FALSE otherwise
	 */
	protected abstract boolean isArchiveTimestamp(SignatureAttribute unsignedAttribute);
	
	/**
	 * Determines if the given {@code unsignedAttribute} is an instance of "timestamp-validation-data" element
	 * @param unsignedAttribute {@link ISignatureAttribute} to process
	 * @return TRUE if the {@code unsignedAttribute} is a TimeStamp Validation Data, FALSE otherwise
	 */
	protected abstract boolean isTimeStampValidationData(SignatureAttribute unsignedAttribute);
	
	/**
	 * Creates a timestamp token from the provided {@code signatureAttribute}
	 * @param signatureAttribute {@link ISignatureAttribute} to create timestamp from
	 * @param timestampType a target {@link TimestampType}
	 * @return {@link TimestampToken}
	 */
	protected abstract TimestampToken makeTimestampToken(SignatureAttribute signatureAttribute, TimestampType timestampType);
	
	/**
	 * Returns a list of {@link TimestampedReference}s obtained from the {@code signatureScopes}
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getAllContentTimestampReferences() {
		final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (SignatureScope signatureScope : signatureScopes) {
				addReference(references, new TimestampedReference(signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));
			}
		}
		return references;
	}
	
	/**
	 * Returns a list of {@link TimestampedReference}s for an "individual-data-objects-timestamp"
	 * NOTE: Used only in XAdES
	 * @param includes - list of {@link TimestampInclude}s
	 * @return a list of {@link TimestampedReference}s
	 */
	protected abstract List<TimestampedReference> getIndividualContentTimestampedReferences(List<TimestampInclude> includes);
	
	/**
	 * Returns a list of {@link TimestampedReference} for a "signature-timestamp" element
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getSignatureTimestampReferences() {
		final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		addReferences(references, getAllContentTimestampReferences());
		addReference(references, new TimestampedReference(signatureId, TimestampedObjectType.SIGNATURE));
		addReferences(references, getSigningCertificateTimestampReferences());
		return references;
	}

	protected List<TimestampedReference> getSigningCertificateTimestampReferences() {
		final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		List<CertificateToken> signingCertificates = certificateSource.getSigningCertificates();
		for (CertificateToken certificateToken : signingCertificates) {
			addReference(references, new TimestampedReference(certificateToken.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		return references;
	}
	
	/**
	 * Returns a list of {@link TimestampedReference} certificate refs found in the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to find references from
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getTimestampedCertificateRefs(SignatureAttribute unsignedAttribute) {
		List<TimestampedReference> timestampedReferences = new ArrayList<TimestampedReference>();
		for (Digest certDigest : getCertificateRefDigests(unsignedAttribute)) {
			CertificateToken certificate = certificateSource.getCertificateTokenByDigest(certDigest);
			if (certificate != null) {
				timestampedReferences.add(new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
			}
		}
		return timestampedReferences;
	}
	
	/**
	 * Returns a list of {@link Digest}s from the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get certRef Digests from
	 * @return list of {@link Digest}s
	 */
	protected abstract List<Digest> getCertificateRefDigests(SignatureAttribute unsignedAttribute);
	
	/**
	 * Returns a list of {@link TimestampedReference} revocation refs found in the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to find references from
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getTimestampedRevocationRefs(SignatureAttribute unsignedAttribute) {
		List<TimestampedReference> timestampedReferences = new ArrayList<TimestampedReference>();
		for (Digest refDigest : getRevocationRefCRLDigests(unsignedAttribute)) {
			CRLBinaryIdentifier identifier = crlSource.getIdentifier(refDigest);
			if (identifier != null) {
				timestampedReferences.add(new TimestampedReference(identifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		
		for (Digest refDigest : getRevocationRefOCSPDigests(unsignedAttribute)) {
			OCSPResponseIdentifier identifier = ocspSource.getIdentifier(refDigest);
			if (identifier != null) {
				timestampedReferences.add(new TimestampedReference(identifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		return timestampedReferences;
	}
	
	/**
	 * Returns a list of CRL revocation ref {@link Digest}s from the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get CRLRef Digests from
	 * @return list of {@link Digest}s
	 */
	protected abstract List<Digest> getRevocationRefCRLDigests(SignatureAttribute unsignedAttribute);
	
	/**
	 * Returns a list of OCSP revocation ref {@link Digest}s from the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get OCSPRef Digests from
	 * @return list of {@link Digest}s
	 */
	protected abstract List<Digest> getRevocationRefOCSPDigests(SignatureAttribute unsignedAttribute);
	
	protected List<TimestampedReference> getTimestampedCertificateValues(SignatureAttribute unsignedAttribute) {
		List<TimestampedReference> timestampedReferences = new ArrayList<TimestampedReference>();
		for (EncapsulatedTokenIdentifier certificateIdentifier : getEncapsulatedCertificateIdentifiers(unsignedAttribute)) {
			timestampedReferences.add(new TimestampedReference(certificateIdentifier.asXmlId(), TimestampedObjectType.CERTIFICATE));
		}
		return timestampedReferences;
	}
	
	/**
	 * Returns a list of {@link EncapsulatedCertificateTokenIdentifier}s obtained from the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get certificate identifiers from
	 * @return list of {@link EncapsulatedCertificateTokenIdentifier}s
	 */
	protected abstract List<EncapsulatedCertificateTokenIdentifier> getEncapsulatedCertificateIdentifiers(SignatureAttribute unsignedAttribute);
	
	protected List<TimestampedReference> getTimestampedRevocationValues(SignatureAttribute unsignedAttribute) {
		List<TimestampedReference> timestampedReferences = new ArrayList<TimestampedReference>();
		for (EncapsulatedTokenIdentifier revocationIdentifier : getEncapsulatedCRLIdentifiers(unsignedAttribute)) {
			timestampedReferences.add(new TimestampedReference(revocationIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
		}
		for (EncapsulatedTokenIdentifier revocationIdentifier : getEncapsulatedOCSPIdentifiers(unsignedAttribute)) {
			timestampedReferences.add(new TimestampedReference(revocationIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
		}
		return timestampedReferences;
	}
	
	/**
	 * Returns a list of {@link CRLBinaryIdentifier}s obtained from the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get CRL identifiers from
	 * @return list of {@link CRLBinaryIdentifier}s
	 */
	protected abstract List<CRLBinaryIdentifier> getEncapsulatedCRLIdentifiers(SignatureAttribute unsignedAttribute);
	
	/**
	 * Returns a list of {@link OCSPResponseIdentifier}s obtained from the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get OCSP identifiers from
	 * @return list of {@link OCSPResponseIdentifier}s
	 */
	protected abstract List<OCSPResponseIdentifier> getEncapsulatedOCSPIdentifiers(SignatureAttribute unsignedAttribute);
	
	/**
	 * Returns a list of {@link TimestampedReference}s encapsulated to the "timestamp-validation-data" {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get timestamped references from
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getTimestampValidationData(SignatureAttribute unsignedAttribute) {
		List<TimestampedReference> timestampedReferences = new ArrayList<TimestampedReference>();
		for (EncapsulatedTokenIdentifier certificateIdentifier : getEncapsulatedCertificateIdentifiers(unsignedAttribute)) {
			timestampedReferences.add(new TimestampedReference(certificateIdentifier.asXmlId(), TimestampedObjectType.CERTIFICATE));
		}
		for (EncapsulatedTokenIdentifier crlIdentifier : getEncapsulatedCRLIdentifiers(unsignedAttribute)) {
			timestampedReferences.add(new TimestampedReference(crlIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
		}
		for (EncapsulatedTokenIdentifier ocspIdentifier : getEncapsulatedOCSPIdentifiers(unsignedAttribute)) {
			timestampedReferences.add(new TimestampedReference(ocspIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
		}
		return timestampedReferences;
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

	private List<TimestampToken> filterSignatureTimestamps(List<TimestampToken> previousTimestampedTimestamp) {
		List<TimestampToken> result = new ArrayList<TimestampToken>();
		for (TimestampToken timestampToken : previousTimestampedTimestamp) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {
				result.add(timestampToken);
			}
		}
		return result;
	}

	protected void addReferencesForPreviousTimestamps(List<TimestampedReference> references, List<TimestampToken> timestampedTimestamps) {
		for (final TimestampToken timestampToken : timestampedTimestamps) {
			addReference(references, new TimestampedReference(timestampToken.getDSSIdAsString(), TimestampedObjectType.TIMESTAMP));
			addEncapsulatedCertificatesFromTimestamp(references, timestampToken);
			addTimestampedReferences(references, timestampToken);
		}
	}
	
	protected void addTimestampedReferences(List<TimestampedReference> references, TimestampToken timestampedTimestamp) {
		for (TimestampedReference timestampedReference : timestampedTimestamp.getTimestampedReferences()) {
			addReference(references, timestampedReference);
		}
	}
	
	private void addEncapsulatedCertificatesFromTimestamp(List<TimestampedReference> references, TimestampToken timestampedTimestamp) {
		List<CertificateToken> certificates = timestampedTimestamp.getCertificates();
		for (final CertificateToken certificate : certificates) {
			addReference(references, new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
	}
	
	/**
	 * Returns {@link ArchiveTimestampType} for the given {@code unsignedAttribute}
	 * @param unsignedAttribute {@link SignatureAttribute} to get archive timestamp type for
	 */
	protected abstract ArchiveTimestampType getArchiveTimestampType(SignatureAttribute unsignedAttribute);
	
	/**
	 * Validates list of all timestamps present in the source
	 */
	protected void validateTimestamps() {
		
		TimestampDataBuilder timestampDataBuilder = getTimestampDataBuilder();

		/*
		 * This validates the content-timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getContentTimestamps()) {
			final byte[] timestampBytes = timestampDataBuilder.getContentTimestampData(timestampToken);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the signature timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getSignatureTimestamps()) {
			final byte[] timestampBytes = timestampDataBuilder.getSignatureTimestampData(timestampToken);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the SigAndRefs timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getTimestampsX1()) {
			final byte[] timestampBytes = timestampDataBuilder.getTimestampX1Data(timestampToken);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the RefsOnly timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getTimestampsX2()) {
			final byte[] timestampBytes = timestampDataBuilder.getTimestampX2Data(timestampToken);
			timestampToken.matchData(timestampBytes);
		}

		/*
		 * This validates the archive timestamp tokensToProcess present in the signature.
		 */
		for (final TimestampToken timestampToken : getArchiveTimestamps()) {
			if (!timestampToken.isProcessed()) {
				final byte[] timestampData = timestampDataBuilder.getArchiveTimestampData(timestampToken);
				timestampToken.matchData(timestampData);
			}
		}
		
	}
	
	/**
	 * Returns a related {@link TimestampDataBuilder}
	 * @return {@link TimestampDataBuilder}
	 */
	protected abstract TimestampDataBuilder getTimestampDataBuilder();

	@Override
	public Map<String, List<CertificateToken>> getCertificateMapWithinTimestamps(boolean skipLastArchiveTimestamp) {
		// We can have more than one chain in the signature : signing certificate, ocsp
		// responder, ...
		Map<String, List<CertificateToken>> certificates = new HashMap<String, List<CertificateToken>>();
		
		int timestampCounter = 0;
		for (final TimestampToken timestampToken : getContentTimestamps()) {
			certificates.put(timestampToken.getTimeStampType().name() + timestampCounter++, timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getTimestampsX1()) {
			certificates.put(timestampToken.getTimeStampType().name() + timestampCounter++, timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getTimestampsX2()) {
			certificates.put(timestampToken.getTimeStampType().name() + timestampCounter++, timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getSignatureTimestamps()) {
			certificates.put(timestampToken.getTimeStampType().name() + timestampCounter++, timestampToken.getCertificates());
		}

		List<TimestampToken> archiveTsps = getArchiveTimestamps();
		int archiveTimestampsSize = archiveTsps.size();
		if (skipLastArchiveTimestamp && archiveTimestampsSize > 0) {
			archiveTimestampsSize--;
		}
		for (int ii = 0; ii < archiveTimestampsSize; ii++) {
			TimestampToken timestampToken = archiveTsps.get(ii);
			certificates.put(timestampToken.getTimeStampType().name() + timestampCounter++, timestampToken.getCertificates());
		}

		return certificates;
	}
	
	@Override
	public Set<CertificateToken> getCertificates() {
		Set<CertificateToken> certificates = new HashSet<CertificateToken>();
		for (List<CertificateToken> certificateTokens : getCertificateMapWithinTimestamps(false).values()) {
			certificates.addAll(certificateTokens);
		}
		return certificates;
	}

}
