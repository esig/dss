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
package eu.europa.esig.dss.policy;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.policy.jaxb.ContainerConstraints;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.EIDAS;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. This
 * is the base class used to implement a
 * specific validation policy
 */
public interface ValidationPolicy {

	/**
	 * This function returns the algorithm expiration date extracted from the 'constraint.xml' file. If the TAG
	 * AlgoExpirationDate is not present within the
	 * constraints {@code null} is returned.
	 *
	 * @param algorithm
	 *            algorithm (SHA1, SHA256, RSA2048...) to be checked
	 * @return expiration date or null
	 */
	Date getAlgorithmExpirationDate(String algorithm, Context context, SubContext subContext);

	/**
	 * Indicates if the signature policy should be checked. If AcceptablePolicies element is absent within the
	 * constraint file then null is returned, otherwise
	 * the list of identifiers is initialised.
	 *
	 * @return {@code LevelConstraint} if SigningTime element is present in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getSignaturePolicyConstraint(Context context);

	/**
	 * Indicates if the signature policy validation should be processed.
	 * If SignaturePolicyIdentifier found, but not relevant SignaturePolicy is retrieved, the check fails.
	 * 
	 * @param context {@link Context}
	 * @return {@link LevelConstraint} if SignaturePolicy shall be identified
	 */
	LevelConstraint getSignaturePolicyIdentifiedConstraint(Context context);

	/**
	 * Indicates if a SignaturePolicyStore unsigned attribute, containing a used policy binaries,
	 * presence shall be checked
	 * 
	 * @param context {@link Context}
	 * @return {@link LevelConstraint} if SignaturePolicyStore presence shall be checked
	 */
	LevelConstraint getSignaturePolicyStorePresentConstraint(Context context);

	/**
	 * Indicates if digest present in a SignaturePolicyIdentifier shall match to the extracted policy content
	 * 
	 * @param context {@link Context}
	 * @return {@link LevelConstraint} if SignaturePolicyIdentifier digest shall match
	 */
	LevelConstraint getSignaturePolicyPolicyHashValid(Context context);

	/**
	 * Indicates if the structural validation should be checked. If StructuralValidation element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if StructuralValidation element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getStructuralValidationConstraint(Context context);

	/**
	 * Indicates if the Signing Certificate attribute should be checked against the certificate chain.
	 * If SigningCertificateRefersCertificateChain element is absent within the constraint file then null is returned.
	 * 
	 * @return {@code LevelConstraint} if SigningCertificateRefersCertificateChain element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateRefersCertificateChainConstraint(Context context);

	/**
	 * Indicates if the whole certificate chain is covered by the Signing Certificate attribute.
	 * If ReferencesToAllCertificateChainPresent element is absent within the constraint file then null is returned.
	 * 
	 * @return {@code LevelConstraint} if ReferencesToAllCertificateChainPresent element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getReferencesToAllCertificateChainPresentConstraint(Context context);

	/**
	 * Indicates if the signed property: signing-time should be checked. If SigningTime element is absent within the
	 * constraint file then null is returned.
	 *
	 * @return {@code LevelConstraint} if SigningTime element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningTimeConstraint(Context context);

	/**
	 * Indicates if the signed property: content-type should be checked. If ContentType element is absent within the
	 * constraint file then null is returned.
	 *
	 * @return {@code ValueConstraint} if ContentType element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentTypeConstraint(Context context);

	/**
	 * Indicates if the signed property: content-hints should be checked. If ContentHints element is absent within the
	 * constraint file then null is returned.
	 *
	 * @return {@code ValueConstraint} if ContentHints element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentHintsConstraint(Context context);

	/**
	 * Indicates if the signed property: content-identifier should be checked. If ContentIdentifier element is absent
	 * within the constraint file then null is
	 * returned.
	 *
	 * @return {@code ValueConstraint} if ContentIdentifier element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentIdentifierConstraint(Context context);

	/**
	 * Indicates if the signed property: message-digest (for CAdES) or SignedProperties (for XAdES) should be checked.
	 * If the relative element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelConstraint} if message-digests/SignedProperties element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getMessageDigestOrSignedPropertiesConstraint(Context context);

	/**
	 * Indicates if the signed property: commitment-type-indication should be checked. If CommitmentTypeIndication
	 * element is absent within the constraint file
	 * then null is returned, otherwise the list of identifiers is initialised.
	 *
	 * @return {@code MultiValuesConstraint} if CommitmentTypeIndication element is present in the constraint file, null
	 *         otherwise.
	 */
	MultiValuesConstraint getCommitmentTypeIndicationConstraint(Context context);

	/**
	 * Indicates if the signed property: signer-location should be checked. If SignerLocation element is absent within
	 * the constraint file then null is
	 * returned.
	 *
	 * @return {@code LevelConstraint} if SignerLocation element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignerLocationConstraint(Context context);

	/**
	 * Indicates if the signed property: content-time-stamp should be checked. If ContentTimeStamp element is absent
	 * within the constraint file then null is
	 * returned.
	 *
	 * @return {@code LevelConstraint} if ContentTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getContentTimestampConstraint(Context context);

	/**
	 * Indicates if the unsigned property: claimed-role should be checked. If ClaimedRoles element is absent within the
	 * constraint file then null is returned.
	 *
	 * @return {@code MultiValuesConstraint} if ClaimedRoles element is present in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getClaimedRoleConstraint(Context context);

	/**
	 * Return the mandated signer role.
	 *
	 * @return
	 */
	MultiValuesConstraint getCertifiedRolesConstraint(Context context);

	/**
	 * Returns the name of the policy.
	 *
	 * @return
	 */
	String getPolicyName();

	/**
	 * Returns the policy description.
	 *
	 * @return
	 */
	String getPolicyDescription();

	/**
	 * This method creates the {@code SignatureCryptographicConstraint} corresponding to the context parameter. If
	 * AcceptableEncryptionAlgo is not present in
	 * the constraint file the null is returned.
	 *
	 * @param context
	 *            The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @return {@code SignatureCryptographicConstraint} if AcceptableEncryptionAlgo for a given context element is
	 *         present in the constraint file, null
	 *         otherwise.
	 */
	CryptographicConstraint getSignatureCryptographicConstraint(Context context);

	/**
	 * This method creates the {@code SignatureCryptographicConstraint} corresponding to the context parameter. If
	 * AcceptableEncryptionAlgo is not present in
	 * the constraint file the null is returned.
	 *
	 * @param context
	 *            The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @param subContext
	 *            the sub context of the signature cryptographic constraints: EMPTY (signature itself),
	 *            SigningCertificate, CACertificate
	 * @return {@code SignatureCryptographicConstraint} if AcceptableEncryptionAlgo for a given context element is
	 *         present in the constraint file, null
	 *         otherwise.
	 */
	CryptographicConstraint getCertificateCryptographicConstraint(Context context, SubContext subContext);

	/**
	 * @param context
	 * @param subContext
	 * @return {@code LevelConstraint} if key-usage for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	MultiValuesConstraint getCertificateKeyUsageConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificateExtendedKeyUsageConstraint(Context context, SubContext subContext);

	/**
	 * @param context
	 * @param subContext
	 * @return {@code LevelConstraint} if Expiration for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getCertificateNotExpiredConstraint(Context context, SubContext subContext);

	/**
	 * This constraint requests the presence of the trust anchor in the certificate chain.
	 *
	 * @param context
	 * @return {@code LevelConstraint} if ProspectiveCertificateChain element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelConstraint getProspectiveCertificateChainConstraint(Context context);

	/**
	 * @param context
	 * @param subContext
	 * @return {@code LevelConstraint} if Signature for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getCertificateSignatureConstraint(Context context, SubContext subContext);

	/**
	 * The method returns UnknownStatus constraint
	 * 
	 * @return {@link LevelConstraint}
	 */
	LevelConstraint getUnknownStatusConstraint();

	/**
	 * The method returns OCSPCertHashPresent constraint
	 * 
	 * @return {@link LevelConstraint}
	 */
	LevelConstraint getOCSPResponseCertHashPresentConstraint();

	/**
	 * The method returns OCSPCertHashMatch constraint
	 * 
	 * @return {@link LevelConstraint}
	 */
	LevelConstraint getOCSPResponseCertHashMatchConstraint();

	/**
	 * The method returns SelfIssuedOCSP constraint
	 * 
	 * @return {@link LevelConstraint}
	 */
	LevelConstraint getSelfIssuedOCSPConstraint();

	/**
	 * @param context
	 * @return {@code LevelConstraint} if RevocationDataAvailable for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getRevocationDataAvailableConstraint(Context context, SubContext subContext);

	LevelConstraint getRevocationDataNextUpdatePresentConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificateRevocationFreshnessConstraint(Context context, SubContext subContext);

	/**
	 * @return {@code LevelConstraint} if Revoked for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getCertificateNotRevokedConstraint(Context context, SubContext subContext);

	/**
	 * @return {@code LevelConstraint} if OnHold for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getCertificateNotOnHoldConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificateNotSelfSignedConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificateSelfSignedConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getTrustedServiceTypeIdentifierConstraint(Context context);

	MultiValuesConstraint getTrustedServiceStatusConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if Qualification for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelConstraint getCertificateQualificationConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is mandated to be supported by a secure
	 * signature creation device (QSCD).
	 *
	 * @return {@code LevelConstraint} if SupportedByQSCD for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelConstraint getCertificateSupportedByQSCDConstraint(Context context, SubContext subContext);

	/**
	 * @return {@code LevelConstraint} if IssuedToLegalPerson for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getCertificateIssuedToLegalPersonConstraint(Context context, SubContext subContext);

	/**
	 * @return {@code LevelConstraint} if Recognition for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelConstraint getSigningCertificateRecognitionConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if SigningCertificateAttribute for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateAttributePresentConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if UnicitySigningCertificate for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getUnicitySigningCertificateAttributeConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if DigestValuePresent for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getSigningCertificateDigestValuePresentConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if DigestValueMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getSigningCertificateDigestValueMatchConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if AllCertDigestsMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
    LevelConstraint getAllSigningCertificateDigestValuesMatchConstraint(Context context);

    /**
	 * @return {@code LevelConstraint} if IssuerSerialMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getSigningCertificateIssuerSerialMatchConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if ReferenceDataExistence for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelConstraint getReferenceDataExistenceConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if ReferenceDataIntact for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelConstraint getReferenceDataIntactConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if ManifestEntryObjectExistence for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getManifestEntryObjectExistenceConstraint(Context context);

	/**
	 * @return {@code SignatureDataIntact} if SignatureIntact for a given context
	 *         element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignatureIntactConstraint(Context context);
	
	/**
	 * @return {@code SignatureDuplicated} if SignatureDuplicated for a given context
	 *         element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignatureDuplicatedConstraint(Context context);
	
	/**
	 * This constraint checks if only one SignerInfo is present into a SignerInformationStore
	 * NOTE: applicable only for PAdES
	 * 
	 * @param context
	 * @return {@code LevelConstraint} if SignerInformationStore element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelConstraint getSignerInformationStoreConstraint(Context context);
	
	/**
	 * Indicates if a PDF page difference check should be proceeded. If PdfPageDifference element is absent within
	 * the constraint file then null is returned.
	 * 
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if PdfPageDifference element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getPdfPageDifferenceConstraint(Context context);
	
	/**
	 * Indicates if a PDF annotation overlapping check should be proceeded. If PdfAnnotationOverlap element is absent within
	 * the constraint file then null is returned.
	 * 
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if PdfAnnotationOverlap element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getPdfAnnotationOverlapConstraint(Context context);
	
	/**
	 * Indicates if a PDF visual difference check should be proceeded. If PdfVisualDifference element is absent within
	 * the constraint file then null is returned.
	 * 
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if PdfVisualDifference element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getPdfVisualDifferenceConstraint(Context context);

	/**
	 * This constraint checks if the certificate is not expired on best-signature-time
	 */
	LevelConstraint getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint();

	LevelConstraint getTimestampCoherenceConstraint();

	TimeConstraint getTimestampDelayConstraint();

	LevelConstraint getRevocationTimeAgainstBestSignatureTime();

	TimeConstraint getRevocationFreshnessConstraint();

	LevelConstraint getCounterSignatureConstraint(Context context);

	MultiValuesConstraint getSignatureFormatConstraint(Context context);

	MultiValuesConstraint getCertificateCountryConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificateOrganizationNameConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificateOrganizationUnitConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificateSurnameConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificateGivenNameConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificateCommonNameConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificatePseudonymConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificatePseudoUsageConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificateSerialNumberConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificateAuthorityInfoAccessPresentConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificateRevocationInfoAccessPresentConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificatePolicyIdsConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getCertificateQCStatementIdsConstraint(Context context, SubContext subContext);

	LevelConstraint getCertificateIssuedToNaturalPersonConstraint(Context context, SubContext subContext);

	MultiValuesConstraint getAcceptedContainerTypesConstraint();

	LevelConstraint getZipCommentPresentConstraint();

	MultiValuesConstraint getAcceptedZipCommentsConstraint();

	LevelConstraint getMimeTypeFilePresentConstraint();

	MultiValuesConstraint getAcceptedMimeTypeContentsConstraint();

	LevelConstraint getAllFilesSignedConstraint();

	LevelConstraint getManifestFilePresentConstraint();

	LevelConstraint getSignedFilesPresentConstraint();

	LevelConstraint getFullScopeConstraint();

	/* Article 32 */

	boolean isEIDASConstraintPresent();

	TimeConstraint getTLFreshnessConstraint();

	LevelConstraint getTLWellSignedConstraint();

	LevelConstraint getTLNotExpiredConstraint();

	ValueConstraint getTLVersionConstraint();

	/**
	 * Returns the used validation model (default is SHELL). Alternatives are CHAIN
	 * and HYBRID
	 * 
	 * @return the validation model to be used
	 */
	Model getValidationModel();
	
	ContainerConstraints getContainerConstraints();

	SignatureConstraints getSignatureConstraints();
	
	SignatureConstraints getCounterSignatureConstraints();

	TimestampConstraints getTimestampConstraints();

	RevocationConstraints getRevocationConstraints();

	EIDAS getEIDASConstraints();

	CryptographicConstraint getCryptographic();

}
