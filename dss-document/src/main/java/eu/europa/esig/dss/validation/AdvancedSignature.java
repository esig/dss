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

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;
import eu.europa.esig.dss.x509.SignatureForm;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;

/**
 * Provides an abstraction for an Advanced Electronic Signature. This ease the validation process. Every signature
 * format : XAdES, CAdES and PAdES are treated the same.
 */
public interface AdvancedSignature extends Serializable {

	/**
	 * @return in the case of the detached signature this is the {@code List} of signed contents.
	 */
	List<DSSDocument> getDetachedContents();

	/**
	 * This method allows to set the signed contents in the case of the detached signature.
	 *
	 * @param detachedContents array of {@code DSSDocument} representing the signed detached contents.
	 */
	void setDetachedContents(final DSSDocument... detachedContents);


	/**
	 * This method allows to set the signed contents in the case of the detached signature.
	 *
	 * @param detachedContents {@code List} of {@code DSSDocument} representing the signed detached contents.
	 */
	void setDetachedContents(final List<DSSDocument> detachedContents);

	/**
	 * @return This method returns the provided signing certificate or {@code null}
	 */
	CertificateToken getProvidedSigningCertificateToken();

	/**
	 * This method allows to provide a signing certificate to be used in the validation process. It can happen in the case of a non-AdES signature without the signing certificate
	 * within the signature.
	 *
	 * @param certificateToken {@code CertificateToken} representing the signing certificate token.
	 */
	void setProvidedSigningCertificateToken(final CertificateToken certificateToken);

	/**
	 * Specifies the format of the signature
	 */
	SignatureForm getSignatureForm();

	/**
	 * Retrieves the signature algorithm (or cipher) used for generating the signature.
	 * XAdES: http://www.w3.org/TR/2013/NOTE-xmlsec-algorithms-20130411/
	 *
	 * @return {@code EncryptionAlgorithm}
	 */
	EncryptionAlgorithm getEncryptionAlgorithm();

	/**
	 * Retrieves the signature algorithm (or cipher) used for generating the signature.
	 * XAdES: http://www.w3.org/TR/2013/NOTE-xmlsec-algorithms-20130411/
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
	 * @return
	 */
	SignatureCertificateSource getCertificateSource();

	/**
	 * Gets a CRL source which contains ALL CRLs embedded in the signature.
	 *
	 * @return
	 */
	OfflineCRLSource getCRLSource();

	/**
	 * Gets an OCSP source which contains ALL OCSP responses embedded in the signature.
	 *
	 * @return
	 */
	OfflineOCSPSource getOCSPSource();

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
	 * @param masterSignature {@code AdvancedSignature}
	 */
	void setMasterSignature(final AdvancedSignature masterSignature);

	/**
	 * @return {@code AdvancedSignature}
	 */
	AdvancedSignature getMasterSignature();

	/**
	 * This method returns the signing certificate token or null if there is no valid signing certificate. Note that to determinate the signing certificate the signature must be
	 * validated: the method {@code checkSignatureIntegrity} must be called.
	 *
	 * @return
	 */
	CertificateToken getSigningCertificateToken();

	/**
	 * Verifies the signature integrity; checks if the signed content has not been tampered with. In the case of a non-AdES signature no including the signing certificate then the
	 * latter  must be provided by calling {@code setProvidedSigningCertificateToken} In the case of a detached signature the signed content must be provided by calling {@code
	 * setProvidedSigningCertificateToken}
	 *
	 * @return SignatureCryptographicVerification with all the information collected during the validation process.
	 */
	SignatureCryptographicVerification checkSignatureIntegrity();

	/**
	 * This method checks the protection of the certificates included within the signature (XAdES: KeyInfo) against the substitution attack.
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
	 * Returns the content type of the signed data
	 *
	 * @return content type as {@code String}
	 */
	String getContentType();

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
	 * @reutrn a list of certificate contained within the signature
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
	 * @param timestampToken {@code TimestampToken} or null during the creation process
	 * @param canonicalizationMethod canonicalization method
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
	 * @return {@code List} of {@code TimestampToken}
	 */
	List<TimestampToken> getArchiveTimestamps();

	/**
	 * Archive timestamp seals the data of the signature in a specific order. We need to retrieve the data for each
	 * timestamp.
	 *
	 * @param timestampToken null when adding a new archive timestamp
	 * @param canonicalizationMethod
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getArchiveTimestampData(final TimestampToken timestampToken, String canonicalizationMethod);

	/**
	 * Returns a list of counter signatures applied to this signature
	 *
	 * @return a {@code List} of {@code AdvancedSignatures} representing the counter signatures
	 */
	List<AdvancedSignature> getCounterSignatures();

	/**
	 * Returns the {@code List} of {@code TimestampReference} representing digest value of the certification path references and the revocation status references. (XAdES
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
	 * @return The list of CRLRefs contained in the Signature
	 */
	List<CRLRef> getCRLRefs();

	/**
	 * @return The list of OCSPRef contained in the Signature
	 */
	List<OCSPRef> getOCSPRefs();

	/**
	 * This method returns the DSS unique signature id. It allows to unambiguously identify each signature.
	 *
	 * @return The signature unique Id
	 */
	String getId();

	/**
	 * Returns the set of digest algorithms used to build the certificate's digest. For example, these digests are
	 * referenced in CompleteCertificateRefs in the case of XAdES signature.
	 *
	 * @return
	 */
	Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms();

	/**
	 * @param signatureLevel {@code SignatureLevel} to be checked
	 * @return true if the signature contains the data needed for this {@code SignatureLevel}. Doesn't mean any validity of the data found.
	 */
	boolean isDataForSignatureLevelPresent(final SignatureLevel signatureLevel);

	SignatureLevel getDataFoundUpToLevel();

	/**
	 * @return the list of signature levels for this type of signature, in the simple to complete order. Example: B,T,LT,LTA
	 */
	SignatureLevel[] getSignatureLevels();

	void prepareTimestamps(ValidationContext validationContext);

	void validateTimestamps();

	/**
	 * This method allows the structure validation of the signature. In the case of an XML signature a validation against XSD schema is performed.
	 *
	 * @return null if the validation does not apply, true if the structure is valid otherwise false
	 */
	String validateStructure();
}
