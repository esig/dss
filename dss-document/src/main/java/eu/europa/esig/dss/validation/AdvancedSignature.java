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

import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.revocation.RevocationRef;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.crl.SignatureCRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;

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
	 * Returns the claimed role of the signer.
	 *
	 * @return array of the claimed roles as {@code String} array
	 */
	String[] getClaimedSignerRoles();

	/**
	 * Returns the certified role of the signer.
	 *
	 * @return array of the certified roles
	 */
	List<CertifiedRole> getCertifiedSignerRoles();

	/**
	 * Get certificates embedded in the signature
	 *
	 * @return a list of certificate contained within the signature
	 */
	List<CertificateToken> getCertificates();

	/**
	 * Returns the content timestamps
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getContentTimestamps();

	/**
	 * Returns the content timestamp data (timestamped or to be).
	 *
	 * @param timestampToken
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getContentTimestampData(final TimestampToken timestampToken);

	/**
	 * Returns the signature timestamps
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getSignatureTimestamps();

	/**
	 * Returns the data (signature value) that was timestamped by the SignatureTimeStamp for the given timestamp.
	 *
	 * @param timestampToken
	 * @param canonicalizationMethod
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod);

	/**
	 * Returns the time-stamp which is placed on the digital signature (XAdES example: ds:SignatureValue element), the
	 * signature time-stamp(s) present in the AdES-T form, the certification path references and the revocation status
	 * references.
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getTimestampsX1();

	/**
	 * Returns the data to be time-stamped. The data contains the digital signature (XAdES example: ds:SignatureValue
	 * element), the signature time-stamp(s) present in the AdES-T form, the certification path references and the
	 * revocation status references.
	 *
	 * @param timestampToken
	 *            {@code TimestampToken} or null during the creation process
	 * @param canonicalizationMethod
	 *            canonicalization method
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod);

	/**
	 * Returns the time-stamp which is computed over the concatenation of CompleteCertificateRefs and
	 * CompleteRevocationRefs elements (XAdES example).
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getTimestampsX2();

	/**
	 * Returns the data to be time-stamped which contains the concatenation of CompleteCertificateRefs and
	 * CompleteRevocationRefs elements (XAdES example).
	 *
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod);

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
	 * Archive timestamp seals the data of the signature in a specific order. We need to retrieve the data for each
	 * timestamp.
	 *
	 * @param timestampToken
	 *            null when adding a new archive timestamp
	 * @param canonicalizationMethod
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getArchiveTimestampData(final TimestampToken timestampToken, String canonicalizationMethod);

	/**
	 * This method allows to add an external timestamp. The given timestamp must be checked before.
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
	 * Returns the {@code List} of {@code TimestampReference} representing digest value of the certification path
	 * references and the revocation status references. (XAdES
	 * example: CompleteCertificateRefs and CompleteRevocationRefs elements)
	 *
	 * @return a {@code List} of {@code TimestampReference}
	 */
	List<TimestampReference> getTimestampedReferences();

	/**
	 * Retrieve list of certificate ref
	 *
	 * @return {@code List} of {@code CertificateRef}
	 */
	List<CertificateRef> getCertificateRefs();

	/**
	 * This method returns the DSS unique signature id. It allows to unambiguously identify each signature.
	 *
	 * @return The signature unique Id
	 */
	String getId();

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

	void validateTimestamps();

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
	 * Returns individual validation foreach reference (XAdES) or for the
	 * message-imprint (CAdES)
	 * 
	 * @return a list with one or more {@code ReferenceValidation}
	 */
	List<ReferenceValidation> getReferenceValidations();
	
	// ------------------------ TS 119 102-2 Specifics

	/**
	 * Retrieves the set of all {@link RevocationToken}s in the signature
	 * @return list of {@link RevocationToken}s
	 */
	Set<RevocationToken> getAllRevocationTokens();
	
	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'RevocationValues' element
	 * NOTE: Applicable only for CAdES and XAdES revocation sources
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'AttributeRevocationValues' element
	 * NOTE: Applicable only for XAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getAttributeRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'TimestampValidationData/RevocationValues' element
	 * NOTE: Applicable only for XAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getTimestampRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'DSS' dictionary
	 * NOTE: Applicable only for PAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getDSSDictionaryRevocationTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'VRI' dictionary
	 * NOTE: Applicable only for PAdES revocation source
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getVRIDictionaryRevocationTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'CompleteRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getCompleteRevocationTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'AttributeRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link RevocationToken}s
	 */
	List<RevocationToken> getAttributeRevocationTokens();
	
	/**
	 * Retrieves a list of all {@link CRLRef}s present in 'CompleteRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link CRLRef}s
	 */
	List<CRLRef> getCompleteRevocationCRLReferences();
	
	/**
	 * Retrieves a list of all {@link CRLRef}s present in 'AttributeRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link CRLRef}s
	 */
	List<CRLRef> getAttributeRevocationCRLReferences();
	
	/**
	 * Retrieves a list of all {@link OCSPRef}s present in 'CompleteRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link OCSPRef}s
	 */
	List<OCSPRef> getCompleteRevocationOCSPReferences();
	
	/**
	 * Retrieves a list of all {@link OCSPRef}s present in 'AttributeRevocationRefs' element
	 * NOTE: Applicable only for XAdES and CAdES revocation sources
	 * @return list of {@link OCSPRef}s
	 */
	List<OCSPRef> getAttributeRevocationOCSPReferences();
	
	/**
	 * Retrieves a list of all found {@link RevocationRef}s present in the signature
	 * @return list of {@link RevocationRef}s
	 */
	List<RevocationRef> getAllFoundRevocationRefs();
	
	/**
	 * Retrieves a list of found {@link RevocationRef}s for the given {@code revocationToken}
	 * @param revocationToken {@link RevocationToken} to get references for
	 * @return list of {@link RevocationRef}s
	 */
	List<RevocationRef> findRefsForRevocationToken(RevocationToken revocationToken);

	/**
	 * Retrieves a list of found {@link RevocationRef}s which were not assigned to
	 * one of used {@code revocationToken}s
	 * 
	 * @return list of {@link RevocationRef}s
	 */
	List<RevocationRef> getOrphanRevocationRefs();

	// ------------------------ CAdES Specifics for TS 119 102-2

	byte[] getMessageDigestValue();

	// ------------------------ PDF Specifics for TS 119 102-2

	String getSignatureName();

	String getFilter();

	String getSubFilter();

	String getContactInfo();

	String getReason();
	
	int[] getSignatureByteRange();

}
