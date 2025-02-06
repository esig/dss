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
package eu.europa.esig.dss.spi.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.signature.CommitmentTypeIndication;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.signature.SignatureDigestReference;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.signature.SignatureProductionPlace;
import eu.europa.esig.dss.model.signature.SignerRole;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.signature.identifier.SignatureIdentifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * Provides an abstraction for an Advanced Electronic Signature. This ease the validation process. Every signature
 * format : XAdES, CAdES and PAdES are treated the same.
 */
public interface AdvancedSignature extends IdentifierBasedObject, Serializable {

	/**
	 * This method returns the signature filename (useful for ASiC and multiple signature files)
	 *
	 * @return the signature filename
	 */
	String getFilename();

	/**
	 * This method allows to set the signature filename (useful in case of ASiC)
	 *
	 * @param filename {@link String}
	 */
	void setFilename(String filename);

	/**
	 * Returns detached contents
	 *
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
	 * Returns container's content
	 *
	 * @return in case of ASiC-S signature returns a list of an archive container documents
	 */
	List<DSSDocument> getContainerContents();
	
	/**
	 * This method allows to set the archive container contents in the case of ASiC-S signature.
	 *
	 * @param containerContents
	 *            {@code List} of {@code DSSDocument} representing the archive container contents.
	 */
	void setContainerContents(final List<DSSDocument> containerContents);

	/**
	 * This method returns a related {@code ManifestFile} in the case of ASiC-E signature.
	 *
	 * @return manifestFile {@link ManifestFile}
	 */
	ManifestFile getManifestFile();

	/**
	 * This method allows to set a manifest file in the case of ASiC-E signature.
	 *
	 * @param manifestFile
	 *            {@code ManifestFile}
	 */
	void setManifestFile(ManifestFile manifestFile);

	/**
	 * Set a certificate source which allows to find the signing certificate by kid
	 * or certificate's digest
	 * 
	 * @param signingCertificateSource the certificate source to resolve missing
	 *                                 signing certificate
	 */
	void setSigningCertificateSource(CertificateSource signingCertificateSource);

	/**
	 * Specifies the format of the signature
	 *
	 * @return {@link SignatureForm}
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
	 * Returns the signing time included within the signature.
	 *
	 * @return {@code Date} representing the signing time or null
	 */
	Date getSigningTime();

	/**
	 * Gets a certificate source which contains ALL certificates embedded in the signature.
	 *
	 * @return {@link SignatureCertificateSource}
	 */
	SignatureCertificateSource getCertificateSource();

	/**
	 * Gets a ListCertificateSource representing a merged source from {@code signatureCertificateSource} and 
	 * all included to the signature timestamp objects
	 * 
	 * @return {@link ListCertificateSource}
	 */
	ListCertificateSource getCompleteCertificateSource();

	/**
	 * Gets a CRL source which contains ALL CRLs embedded in the signature.
	 *
	 * @return {@code OfflineRevocationSource}
	 */
	OfflineRevocationSource<CRL> getCRLSource();

	/**
	 * Gets an OCSP source which contains ALL OCSP responses embedded in the
	 * signature.
	 *
	 * @return {@code OfflineRevocationSource}
	 */
	OfflineRevocationSource<OCSP> getOCSPSource();
	
	/**
	 * Gets a ListRevocationSource representing a merged source from
	 * {@code signatureCRLSourse} and all included to the signature timestamp
	 * objects
	 * 
	 * @return {@link ListRevocationSource}
	 */
	ListRevocationSource<CRL> getCompleteCRLSource();
	
	/**
	 * Gets a ListRevocationSource representing a merged source from
	 * {@code signatureOCSPSourse} and all included to the signature timestamp
	 * objects
	 * 
	 * @return {@link ListRevocationSource}
	 */
	ListRevocationSource<OCSP> getCompleteOCSPSource();
	
	/**
	 * Gets a Signature Timestamp source which contains ALL timestamps embedded in the signature.
	 *
	 * @return {@code SignatureTimestampSource}
	 */
	TimestampSource getTimestampSource();

	/**
	 * Gets an object containing the signing certificate or information indicating why it is impossible to extract it
	 * from the signature. If the signing certificate is identified then it is cached and the subsequent calls to this
	 * method will return this cached value. This method never returns null.
	 *
	 * @return {@link CandidatesForSigningCertificate}
	 */
	CandidatesForSigningCertificate getCandidatesForSigningCertificate();

	/**
	 * This method creates an offline copy of {@code certificateVerifier} and instantiates a {@code BaselineRequirementsChecker}
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	void initBaselineRequirementsChecker(CertificateVerifier certificateVerifier);

	/**
	 * This setter allows to indicate the master signature. It means that this is a countersignature.
	 *
	 * @param masterSignature
	 *            {@code AdvancedSignature}
	 */
	void setMasterSignature(final AdvancedSignature masterSignature);

	/**
	 * Gets master signature
	 *
	 * @return {@code AdvancedSignature}
	 */
	AdvancedSignature getMasterSignature();
	
	/**
	 * Checks if the current signature is a counter signature (i.e. has a Master signature)
	 * 
	 * @return TRUE if it is a counter signature, FALSE otherwise
	 */
	boolean isCounterSignature();

	/**
	 * This method returns the signing certificate token or null if there is no valid signing certificate. Note that to
	 * determinate the signing certificate the signature must be
	 * validated: the method {@code checkSignatureIntegrity} must be called.
	 *
	 * @return {@link CertificateToken}
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
	 * Gets signature's cryptographic validation result
	 *
	 * @return SignatureCryptographicVerification with all the information collected during the validation process.
	 */
	SignatureCryptographicVerification getSignatureCryptographicVerification();

	/**
	 * Returns the Signature Policy OID from the signature.
	 *
	 * @return {@code SignaturePolicy}
	 */
	SignaturePolicy getSignaturePolicy();

	/**
	 * Returns the Signature Policy Store from the signature
	 * 
	 * @return {@code SignaturePolicyStore}
	 */
	SignaturePolicyStore getSignaturePolicyStore();

	/**
	 * Returns information about the place where the signature was generated
	 *
	 * @return {@code SignatureProductionPlace}
	 */
	SignatureProductionPlace getSignatureProductionPlace();

	/**
	 * This method obtains the information concerning commitment type indication linked to the signature
	 *
	 * @return a list of {@code CommitmentTypeIndication}s
	 */
	List<CommitmentTypeIndication> getCommitmentTypeIndications();

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
	 * Returns the list of roles of the signer.
	 *
	 * @return list of the {@link SignerRole}s
	 */
	List<SignerRole> getSignerRoles();

	/**
	 * Returns the list of embedded signed assertions.
	 *
	 * @return list of the assertions s
	 */
	List<SignerRole> getSignedAssertions();

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
	 *
	 * NOTE: applicable only for PAdES
	 *
	 * @return {@code List} of {@code TimestampToken}s
	 */
	List<TimestampToken> getDocumentTimestamps();

	/**
	 * Returns a list of detached timestamps
	 *
	 * NOTE: used for ASiC with CAdES only
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getDetachedTimestamps();

	/**
	 * Returns a list of all timestamps found in the signature
	 * 
	 * @return {@code List} of {@code TimestampToken}s
	 */
	List<TimestampToken> getAllTimestamps();

	/**
	 * This method allows to add an external timestamp. The given timestamp must be processed before.
	 *
	 * NOTE: The method is supported only for CAdES signatures
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
	 * Returns a list of embedded evidence records
	 *
	 * @return a list of {@link EvidenceRecord}s
	 */
	List<EvidenceRecord> getEmbeddedEvidenceRecords();

	/**
	 * Adds an evidence record covering the signature file
	 *
	 * @param evidenceRecord {@link EvidenceRecord}
	 */
	void addExternalEvidenceRecord(EvidenceRecord evidenceRecord);

	/**
	 * Returns a list of detached evidence records
	 *
	 * @return a list of {@link EvidenceRecord}s
	 */
	List<EvidenceRecord> getDetachedEvidenceRecords();

	/**
	 * Returns a list of all evidence records
	 *
	 * @return a list of {@link EvidenceRecord}s
	 */
	List<EvidenceRecord> getAllEvidenceRecords();
	
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
	 * This method returns the signature level
	 * 
	 * @return a value of {@link SignatureLevel}
	 */
	SignatureLevel getDataFoundUpToLevel();

	/**
	 * Checks if the signature is conformant to AdES-BASELINE-B level
	 *
	 * @return TRUE if the B-level is present, FALSE otherwise
	 */
	boolean hasBProfile();

	/**
	 * Checks if the T-level is present in the signature
	 *
	 * @return TRUE if the T-level is present, FALSE otherwise
	 */
	boolean hasTProfile();

	/**
	 * Checks if the LT-level is present in the signature
	 *
	 * @return TRUE if the LT-level is present, FALSE otherwise
	 */
	boolean hasLTProfile();

	/**
	 * Checks if the LTA-level is present in the signature
	 *
	 * @return TRUE if the LTA-level is present, FALSE otherwise
	 */
	boolean hasLTAProfile();

	/**
	 * Checks the presence of signing certificate covered by the signature, what is the proof -BES profile existence
	 *
	 * @return true if BES Profile is detected
	 */
	boolean hasBESProfile();

	/**
	 * Checks the presence of SignaturePolicyIdentifier element in the signature,
	 * what is the proof -EPES profile existence
	 *
	 * @return true if EPES Profile is detected
	 */
	boolean hasEPESProfile();

	/**
	 * Checks the presence of SignatureTimeStamp element in the signature, what is the proof -T profile existence
	 *
	 * @return true if T Profile is detected
	 */
	boolean hasExtendedTProfile();

	/**
	 * Checks the presence of CompleteCertificateRefs and CompleteRevocationRefs segments in the signature,
	 * what is the proof -C profile existence
	 *
	 * @return true if C Profile is detected
	 */
	boolean hasCProfile();

	/**
	 * Checks the presence of SigAndRefsTimeStamp segment in the signature, what is the proof -X profile existence
	 *
	 * @return true if the -X extension is present
	 */
	boolean hasXProfile();

	/**
	 * Checks the presence of CertificateValues/RevocationValues segment in the signature, what is the proof -XL profile existence
	 *
	 * @return true if the -XL extension is present
	 */
	boolean hasXLProfile();

	/**
	 * Checks the presence of ArchiveTimeStamp element in the signature, what is the proof -A profile existence
	 *
	 * @return true if the -A extension is present
	 */
	boolean hasAProfile();
	
	/**
	 * Checks if all certificate chains present in the signature are self-signed
	 * @return TRUE if all certificates are self-signed, false otherwise
	 */
	boolean areAllSelfSignedCertificates();

	/**
	 * Returns a message if the structure validation fails
	 * 
	 * @return a list of {@link String} error messages if validation fails,
	 *         an empty list if structural validation succeeds
	 */
	List<String> getStructureValidationResult();

	/**
	 * Returns a list of found SignatureScopes
	 * 
	 * @return a list of {@link SignatureScope}s
	 */
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
	 *
	 * @return digital signature value byte array
	 */
	byte[] getSignatureValue();

	/**
	 * Returns individual validation foreach reference (XAdES, JAdES) or for the message-imprint (CAdES)
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
	
	/**
	 * TS 119 102-1 (4.2.8 Data to be signed representation (DTBSR)) :
	 * The DTBS preparation component shall take the DTBSF and hash it according to 
	 * the hash algorithm specified in the cryptographic suite.
	 * 
	 * @return {@link Digest} DTBSR, which is then used to create the signature.
	 */
	Digest getDataToBeSignedRepresentation();

}
