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

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.validation.timestamp.SignatureTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.x509.revocation.RevocationRef;
import eu.europa.esig.dss.x509.revocation.RevocationToken;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;

/**
 * Provides an abstraction for an Advanced Electronic Signature. This ease the validation process. Every signature
 * format : XAdES, CAdES and PAdES are treated the same.
 */
public interface AdvancedSignature extends Serializable {

	/**
	 * This method returns the signature filename (useful for ASiC and multiple signature files)
	 * 
	 * @return the signature filename
	 */
	String getSignatureFilename();

	/**
	 * This method allows to set the signature filename (useful in case of ASiC)
	 */
	void setSignatureFilename(String signatureFilename);

	/**
	 * @return in the case of the detached signature this is the {@code List} of signed contents.
	 */
	List<DSSDocument> getDetachedContents();

	/**
	 * This method allows to set the signed contents in the case of the detached signature.
	 *
	 * @param detachedContents
	 *            {@code List} of {@code DSSDocument} representing the signed detached contents.
	 */
	void setDetachedContents(final List<DSSDocument> detachedContents);
	
	/**
	 * @return in case of ASiC signature returns a list of container documents
	 */
	List<DSSDocument> getContainerContents();
	
	/**
	 * This method allows to set the container contents in the case of ASiC signature.
	 *
	 * @param containerContents
	 *            {@code List} of {@code DSSDocument} representing the container contents.
	 */
	void setContainerContents(final List<DSSDocument> containerContents);

	/**
	 * This method allows to set the manifest files in the case of ASiC-E signature.
	 *
	 * @param manifestFiles
	 *            {@code List} of {@code ManifestFile}s
	 */
	void setManifestFiles(List<ManifestFile> manifestFiles);

	/**
	 * @return in case of ASiC-E signature returns a list of {@link DSSDocument}s contained in the related signature manifest
	 */
	List<DSSDocument> getManifestedDocuments();

	/**
	 * @return This method returns the provided signing certificate or {@code null}
	 */
	CertificateToken getProvidedSigningCertificateToken();

	/**
	 * This method allows to provide a signing certificate to be used in the validation process. It can happen in the
	 * case of a non-AdES signature without the signing certificate
	 * within the signature.
	 *
	 * @param certificateToken
	 *            {@code CertificateToken} representing the signing certificate token.
	 */
	void setProvidedSigningCertificateToken(final CertificateToken certificateToken);

	/**
	 * Specifies the format of the signature
	 */
	SignatureForm getSignatureForm();

	/**
	 * Retrieves the signature algorithm (or cipher) used for generating the signature.
	 *
	 * @return {@code SignatureAlgorithm}
	 */
	SignatureAlgorithm getSignatureAlgorithm();

	/**
	 * Retrieves the encryption algorithm used for generating the signature.
	 *
	 * @return {@code EncryptionAlgorithm}
	 */
	EncryptionAlgorithm getEncryptionAlgorithm();

	/**
	 * Retrieves the digest algorithm used for generating the signature.
	 *
	 * @return {@code DigestAlgorithm}
	 */
	DigestAlgorithm getDigestAlgorithm();

	/**
	 * Retrieves the mask generation function used for generating the signature.
	 *
	 * @return {@code MaskGenerationFunction}
	 */
	MaskGenerationFunction getMaskGenerationFunction();

	/**
	 * Returns the signing time included within the signature.
	 *
	 * @return {@code Date} representing the signing time or null
	 */
	Date getSigningTime();

	/**
	 * Gets a certificate source which contains ALL certificates embedded in the signature.
	 *
	 * @return
	 */
	SignatureCertificateSource getCertificateSource();

	/**
	 * Gets a CRL source which contains ALL CRLs embedded in the signature.
	 *
	 * @return {@code SignatureCRLSource}
	 */
	SignatureCRLSource getCRLSource();

	/**
	 * Gets an OCSP source which contains ALL OCSP responses embedded in the signature.
	 *
	 * @return {@code SignatureOCSPSource}
	 */
	SignatureOCSPSource getOCSPSource();
	
	/**
	 * Gets a ListCRLSource representing a merged source from {@code signatureCRLSourse} and 
	 * all included to the signature timestamp objects
	 * 
	 * @return {@link ListCRLSource}
	 */
	ListCRLSource getCompleteCRLSource();
	
	/**
	 * Gets a ListOCSPSource representing a merged source from {@code signatureOCSPSourse} and 
	 * all included to the signature timestamp objects
	 * 
	 * @return {@link ListOCSPSource}
	 */
	ListOCSPSource getCompleteOCSPSource();
	
	/**
	 * Gets a Signature Timestamp source which contains ALL timestamps embedded in the signature.
	 *
	 * @return {@code SignatureTimestampSource}
	 */
	SignatureTimestampSource getTimestampSource();

	/**
	 * Gets an object containing the signing certificate or information indicating why it is impossible to extract it
	 * from the signature. If the signing certificate is identified then it is cached and the subsequent calls to this
	 * method will return this cached value. This method never returns null.
	 *
	 * @return
	 */
	CandidatesForSigningCertificate getCandidatesForSigningCertificate();

	/**
	 * This setter allows to indicate the master signature. It means that this is a countersignature.
	 *
	 * @param masterSignature
	 *            {@code AdvancedSignature}
	 */
	void setMasterSignature(final AdvancedSignature masterSignature);

	/**
	 * @return {@code AdvancedSignature}
	 */
	AdvancedSignature getMasterSignature();

	/**
	 * This method returns the signing certificate token or null if there is no valid signing certificate. Note that to
	 * determinate the signing certificate the signature must be
	 * validated: the method {@code checkSignatureIntegrity} must be called.
	 *
	 * @return
	 */
	CertificateToken getSigningCertificateToken();

	/**
	 * Verifies the signature integrity; checks if the signed content has not been tampered with. In the case of a
	 * non-AdES signature no including the signing certificate then the latter must be provided by calling
	 * {@code setProvidedSigningCertificateToken} In the case of a detached signature the signed content must be
	 * provided by calling {@code setProvidedSigningCertificateToken}
	 */
	void checkSignatureIntegrity();

	/**
	 * @return SignatureCryptographicVerification with all the information collected during the validation process.
	 */
	SignatureCryptographicVerification getSignatureCryptographicVerification();

	/**
	 * This method checks the protection of the certificates included within the signature (XAdES: KeyInfo) against the
	 * substitution attack.
	 */
	void checkSigningCertificate();

	/**
	 * Returns the Signature Policy OID from the signature.
	 *
	 * @return {@code SignaturePolicy}
	 */
	SignaturePolicy getPolicyId();

	/**
	 * Returns information about the place where the signature was generated
	 *
	 * @return {@code SignatureProductionPlace}
	 */
	SignatureProductionPlace getSignatureProductionPlace();

	/**
	 * This method obtains the information concerning commitment type indication linked to the signature
	 *
	 * @return {@code CommitmentType}
	 */
	CommitmentType getCommitmentTypeIndication();

	/**
	 * Returns the value of the signed attribute content-type
	 *
	 * @return content type as {@code String}
	 */
	String getContentType();

	/**
	 * Returns the value of the signed attribute mime-type
	 *
	 * @return mime type as {@code String}
	 */
	String getMimeType();

	/**
	 * @return content identifier as {@code String}
	 */
	String getContentIdentifier();

	/**
	 * @return content hints as {@code String}
	 */
	String getContentHints();

	/**
	 * Returns the list of roles of the signer.
	 *
	 * @return list of the {@link SignerRole}s
	 */
	List<SignerRole> getSignerRoles();

	/**
	 * Returns the claimed roles of the signer.
	 *
	 * @return list of the {@link SignerRole}s
	 */
	List<SignerRole> getClaimedSignerRoles();

	/**
	 * Returns the certified roles of the signer.
	 *
	 * @return list of the {@link SignerRole}s
	 */
	List<SignerRole> getCertifiedSignerRoles();

	/**
	 * Get certificates embedded in the signature
	 *
	 * @return a list of certificate contained within the signature
	 */
	List<CertificateToken> getCertificates();
	

	/**
	 * Returns a list of all certificates found into signature and timestamps
	 * 
	 * @return list of {@link CertificateToken}s
	 */
	List<CertificateToken> getCertificateListWithinSignatureAndTimestamps();

	/**
	 * Returns the content timestamps
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getContentTimestamps();

	/**
	 * Returns the signature timestamps
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getSignatureTimestamps();

	/**
	 * Returns the time-stamp which is placed on the digital signature (XAdES example: ds:SignatureValue element), the
	 * signature time-stamp(s) present in the AdES-T form, the certification path references and the revocation status
	 * references.
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getTimestampsX1();

	/**
	 * Returns the time-stamp which is computed over the concatenation of CompleteCertificateRefs and
	 * CompleteRevocationRefs elements (XAdES example).
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getTimestampsX2();

	/**
	 * Returns the archive Timestamps
	 *
	 * @return {@code List} of {@code TimestampToken}s
	 */
	List<TimestampToken> getArchiveTimestamps();
	
	/**
	 * Returns a list of timestamps defined with the 'DocTimeStamp' type
	 * NOTE: applicable only for PAdES
	 * @return {@code List} of {@code TimestampToken}s
	 */
	List<TimestampToken> getDocumentTimestamps();

	/**
	 * Returns a list of all timestamps found in the signature
	 * 
	 * @return {@code List} of {@code TimestampToken}s
	 */
	List<TimestampToken> getAllTimestamps();

	/**
	 * This method allows to add an external timestamp. The given timestamp must be processed before.
	 * 
	 * @param timestamp
	 *            the timestamp token
	 */
	void addExternalTimestamp(TimestampToken timestamp);

	/**
	 * Returns a list of counter signatures applied to this signature
	 *
	 * @return a {@code List} of {@code AdvancedSignatures} representing the counter signatures
	 */
	List<AdvancedSignature> getCounterSignatures();

	/**
	 * Retrieve list of certificate ref
	 *
	 * @return {@code List} of {@code CertificateRef}
	 */
	List<CertificateRef> getCertificateRefs();
	
	/**
	 * Returns a list of orphan certificate refs, that are not associated to any {@link CertificateToken}
	 * @return list of found {@link CertificateRef}s
	 */
	List<CertificateRef> getOrphanCertificateRefs();
	
	/**
	 * This method returns the {@link SignatureIdentifier}.
	 * 
	 * @return unique {@link SignatureIdentifier}
	 */
	SignatureIdentifier getDSSId();

	/**
	 * This method returns the DSS unique signature id. It allows to unambiguously identify each signature.
	 *
	 * @return The signature unique Id
	 */
	String getId();
	
	/**
	 * This method returns an identifier provided by the Driving Application (DA)
	 * Note: used only for XAdES
	 * 
	 * @return The signature identifier
	 */
	String getDAIdentifier();

	/**
	 * @param signatureLevel
	 *            {@code SignatureLevel} to be checked
	 * @return true if the signature contains the data needed for this {@code SignatureLevel}. Doesn't mean any validity
	 *         of the data found.
	 */
	boolean isDataForSignatureLevelPresent(final SignatureLevel signatureLevel);

	SignatureLevel getDataFoundUpToLevel();

	/**
	 * @return the list of signature levels for this type of signature, in the simple to complete order. Example:
	 *         B,T,LT,LTA
	 */
	SignatureLevel[] getSignatureLevels();

	void prepareTimestamps(ValidationContext validationContext);

	/**
	 * This method allows the structure validation of the signature.
	 */
	void validateStructure();
	
	/**
	 * Fills all the missing {@link CRLToken}s from the given {@code signatureCRLSource}
	 */
	void populateCRLTokenLists(SignatureCRLSource signatureCRLSource);
	
	/**
	 * Fills all the missing {@link OCSPToken}s from the given {@code signatureOCSPSource}
	 */
	void populateOCSPTokenLists(SignatureOCSPSource signatureOCSPSource);

	String getStructureValidationResult();

	void checkSignaturePolicy(SignaturePolicyProvider signaturePolicyDetector);

	void findSignatureScope(SignatureScopeFinder signatureScopeFinder);

	List<SignatureScope> getSignatureScopes();
	
	/**
	 * Returns true if the validation of the signature has been performed only on Signer's Document Representation (SDR).
	 * (An SDR typically is built on a cryptographic hash of the Signer's Document)
	 * @return true of it is DocHashOnly validation, false otherwise
	 */
	boolean isDocHashOnlyValidation();
	
	/**
	 * Returns true if the validation of the signature has been performed only on Data To Be Signed Representation (DTBSR).
	 * 
	 * EN 319 102-1 v1.1.1 (4.2.8 Data to be signed representation (DTBSR)):
	 * The DTBS preparation component shall take the DTBSF and hash it according to the hash algorithm specified in the
	 * cryptographic suite. The result of this process is the DTBSR, which is then used to create the signature. 
	 * NOTE: In order for the produced hash to be representative of the DTBSF, the hashing function has the property 
	 * that it is computationally infeasible to find collisions for the expected signature lifetime. Should the hash
	 * function become weak in the future, additional security measures, such as applying time-stamp tokens,
	 * can be taken. 
	 * @return true of it is HashOnly validation, false otherwise
	 */
	boolean isHashOnlyValidation();
	
	/**
	 * Returns the digital signature value
	 * @return digital signature value byte array
	 */
	byte[] getSignatureValue();

	/**
	 * Returns individual validation foreach reference (XAdES) or for the
	 * message-imprint (CAdES)
	 * 
	 * @return a list with one or more {@code ReferenceValidation}
	 */
	List<ReferenceValidation> getReferenceValidations();
	
	/**
	 * Returns a signature reference element as defined in TS 119 442 - V1.1.1 - 
	 * Electronic Signatures and Infrastructures (ESI), ch. 5.1.4.2.1.3 XML component
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm} to use
	 * @return {@link SignatureDigestReference}
	 */
	SignatureDigestReference getSignatureDigestReference(DigestAlgorithm digestAlgorithm);
	
	// ------------------------ TS 119 102-2 Specifics

	/**
	 * Retrieves the set of all {@code RevocationToken}s in the signature
	 * @return list of {@link RevocationToken}s
	 */
	Set<RevocationToken> getAllRevocationTokens();
	
	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'RevocationValues' element
	 * NOTE: Applicable only for CAdES and XAdES revocation sources
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'AttributeRevocationValues' element
	 * NOTE: Applicable only for XAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getAttributeRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'TimestampValidationData/RevocationValues' element
	 * NOTE: Applicable only for XAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getTimestampValidationDataTokens();

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'DSS' dictionary
	 * NOTE: Applicable only for PAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getDSSDictionaryRevocationTokens();

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'VRI' dictionary
	 * NOTE: Applicable only for PAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getVRIDictionaryRevocationTokens();

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'CompleteRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getCompleteRevocationTokens();

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'AttributeRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getAttributeRevocationTokens();
	
	/**
	 * Retrieves a list of all {@code CRLRef}s present in 'CompleteRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link CRLRef}s
	 */
	List<CRLRef> getCompleteRevocationCRLReferences();
	
	/**
	 * Retrieves a list of all {@code CRLRef}s present in 'AttributeRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link CRLRef}s
	 */
	List<CRLRef> getAttributeRevocationCRLReferences();
	
	/**
	 * Retrieves a list of all {@code CRLRef}s present in a timestamp element
	 * NOTE: Applicable only for CAdES revocation source
	 * @return list of {@link CRLRef}s
	 */
	List<CRLRef> getTimestampRevocationCRLReferences();
	
	/**
	 * Retrieves a list of all {@code OCSPRef}s present in 'CompleteRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link OCSPRef}s
	 */
	List<OCSPRef> getCompleteRevocationOCSPReferences();
	
	/**
	 * Retrieves a list of all {@code OCSPRef}s present in 'AttributeRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link OCSPRef}s
	 */
	List<OCSPRef> getAttributeRevocationOCSPReferences();
	
	/**
	 * Retrieves a list of all {@code OCSPRef}s present in a timestamp element
	 * NOTE: Applicable only for CAdES revocation source
	 * @return list of {@link OCSPRef}s
	 */
	List<OCSPRef> getTimestampRevocationOCSPReferences();
	
	/**
	 * Returns a list of all {@code EncapsulatedRevocationTokenIdentifier}s found in CRL and OCSP sources
	 * @return list of all {@link EncapsulatedRevocationTokenIdentifier}s
	 */
	List<EncapsulatedRevocationTokenIdentifier> getAllFoundRevocationIdentifiers();
	
	/**
	 * Retrieves a list of all found {@code RevocationRef}s present in the signature
	 * @return list of {@link RevocationRef}s
	 */
	List<RevocationRef> getAllFoundRevocationRefs();
	
	/**
	 * Returns a list of all orphan {@code RevocationRef}s found into the signature
	 * @return list of {@link RevocationRef}s
	 */
	List<RevocationRef> getOrphanRevocationRefs();
	
	/**
	 * Retrieves a list of found {@code RevocationRef}s for the given {@code revocationToken}
	 * @param revocationToken {@link RevocationToken} to get references for
	 * @return list of {@link RevocationRef}s
	 */
	List<RevocationRef> findRefsForRevocationToken(RevocationToken revocationToken);
	
	/**
	 * Retrieves a list of found {@code RevocationRef}s for the given {@code revocationIdentifier}
	 * @param revocationIdentifier {@link EncapsulatedRevocationTokenIdentifier} to get references for
	 * @return list of {@link RevocationRef}s
	 */
	List<RevocationRef> findRefsForRevocationIdentifier(EncapsulatedRevocationTokenIdentifier revocationIdentifier);

	// ------------------------ CAdES Specifics for TS 119 102-2

	byte[] getMessageDigestValue();

	// ------------------------ PDF Specifics for TS 119 102-2
	
	String getSignatureFieldName();

	String getSignerName();

	String getFilter();

	String getSubFilter();

	String getContactInfo();

	String getReason();
	
	int[] getSignatureByteRange();

}
