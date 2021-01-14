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
	 * Indicates if the signature policy should be checked. If AcceptablePolicies element is absent within the
	 * constraint file then null is returned, otherwise
	 * the list of identifiers is initialised.
	 *
	 * @param context {@link Context}
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
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if SigningCertificateRefersCertificateChain element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateRefersCertificateChainConstraint(Context context);

	/**
	 * Indicates if the whole certificate chain is covered by the Signing Certificate attribute.
	 * If ReferencesToAllCertificateChainPresent element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if ReferencesToAllCertificateChainPresent element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getReferencesToAllCertificateChainPresentConstraint(Context context);

	/**
	 * Indicates if the signed property: signing-time should be checked. If SigningTime element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if SigningTime element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningTimeConstraint(Context context);

	/**
	 * Indicates if the signed property: content-type should be checked. If ContentType element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code ValueConstraint} if ContentType element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentTypeConstraint(Context context);

	/**
	 * Indicates if the signed property: content-hints should be checked. If ContentHints element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code ValueConstraint} if ContentHints element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentHintsConstraint(Context context);

	/**
	 * Indicates if the signed property: content-identifier should be checked. If ContentIdentifier element is absent
	 * within the constraint file then null is
	 * returned.
	 *
	 * @param context {@link Context}
	 * @return {@code ValueConstraint} if ContentIdentifier element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentIdentifierConstraint(Context context);

	/**
	 * Indicates if the signed property: message-digest (for CAdES) or SignedProperties (for XAdES) should be checked.
	 * If the relative element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if message-digests/SignedProperties element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getMessageDigestOrSignedPropertiesConstraint(Context context);

	/**
	 * Indicates if the signed property: commitment-type-indication should be checked. If CommitmentTypeIndication
	 * element is absent within the constraint file
	 * then null is returned, otherwise the list of identifiers is initialised.
	 *
	 * @param context {@link Context}
	 * @return {@code MultiValuesConstraint} if CommitmentTypeIndication element is present in the constraint file, null
	 *         otherwise.
	 */
	MultiValuesConstraint getCommitmentTypeIndicationConstraint(Context context);

	/**
	 * Indicates if the signed property: signer-location should be checked. If SignerLocation element is absent within
	 * the constraint file then null is
	 * returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if SignerLocation element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignerLocationConstraint(Context context);

	/**
	 * Indicates if the signed property: content-time-stamp should be checked. If ContentTimeStamp element is absent
	 * within the constraint file then null is
	 * returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if ContentTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getContentTimestampConstraint(Context context);

	/**
	 * Indicates if the unsigned property: claimed-role should be checked. If ClaimedRoles element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code MultiValuesConstraint} if ClaimedRoles element is present in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getClaimedRoleConstraint(Context context);

	/**
	 * Return the mandated signer role.
	 *
	 * @param context {@link Context}
	 * @return {@link MultiValuesConstraint}
	 */
	MultiValuesConstraint getCertifiedRolesConstraint(Context context);

	/**
	 * Returns the name of the policy.
	 *
	 * @return {@link String}
	 */
	String getPolicyName();

	/**
	 * Returns the policy description.
	 *
	 * @return {@link String}
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
	 * Returns certificate key usage constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if key-usage for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	MultiValuesConstraint getCertificateKeyUsageConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate extended key usage constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if extended key-usage for a given context element is present in the constraint file,
	 *                                 null otherwise.
	 */
	MultiValuesConstraint getCertificateExtendedKeyUsageConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's not expired constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if Expiration for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getCertificateNotExpiredConstraint(Context context, SubContext subContext);

	/**
	 * This constraint requests the presence of the trust anchor in the certificate chain.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if ProspectiveCertificateChain element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelConstraint getProspectiveCertificateChainConstraint(Context context);

	/**
	 * Returns certificate's signature constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
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
	 * Returns revocation data available constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if RevocationDataAvailable for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getRevocationDataAvailableConstraint(Context context, SubContext subContext);

	/**
	 * Returns revocation data's nextUpdate present constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if RevocationDataNextUpdatePresent for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getRevocationDataNextUpdatePresentConstraint(Context context, SubContext subContext);

	/**
	 * Returns revocation data's freshness constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if RevocationFreshness for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getCertificateRevocationFreshnessConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's not revoked constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if Revoked for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getCertificateNotRevokedConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's not onHold constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if OnHold for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelConstraint getCertificateNotOnHoldConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's not self-signed constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if not self-signed for a given context element is present in the constraint file,
	 *                                 null otherwise.
	 */
	LevelConstraint getCertificateNotSelfSignedConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's self-signed constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if self-signed for a given context element is present in the constraint file,
	 *                                 null otherwise.
	 */
	LevelConstraint getCertificateSelfSignedConstraint(Context context, SubContext subContext);

	/**
	 * Returns trusted service type identifier constraint
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if trusted service type identifier for a given context element is present in
	 *                                 the constraint file, null otherwise.
	 */
	MultiValuesConstraint getTrustedServiceTypeIdentifierConstraint(Context context);

	/**
	 * Returns trusted service status constraint
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if trusted service status for a given context element is present in
	 *                                 the constraint file, null otherwise.
	 */
	MultiValuesConstraint getTrustedServiceStatusConstraint(Context context);

	/**
	 * Indicates if the end user certificate is qualified.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if Qualification for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelConstraint getCertificateQualificationConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is mandated to be supported by a secure
	 * signature creation device (QSCD).
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if SupportedByQSCD for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelConstraint getCertificateSupportedByQSCDConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the country or set of countries under the legislation of which the certificate is issued as a
	 * qualified certificate is present.
	 *
	 * NOTE: in order to verify the EU compliance, the value shall be empty (no QcCCLegislation is allowed)
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} the country or set of countries under the legislation of which
	 * 		the certificate is issued as a qualified certificate
	 */
	MultiValuesConstraint getCertificateQcCCLegislationConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is issued to a legal person.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if IssuedToLegalPerson for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getCertificateIssuedToLegalPersonConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is issued to a natural person.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if Recognition for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelConstraint getSigningCertificateRecognitionConstraint(Context context);

	/**
	 * Indicates if the signing certificate attribute is present
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if SigningCertificateAttribute for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateAttributePresentConstraint(Context context);

	/**
	 * Indicates if the signing certificate is not ambiguously determines
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if UnicitySigningCertificate for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getUnicitySigningCertificateAttributeConstraint(Context context);

	/**
	 * Indicates if the signing certificate reference's digest value is present
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if DigestValuePresent for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getSigningCertificateDigestValuePresentConstraint(Context context);

	/**
	 * Indicates if the signing certificate reference's digest value matches
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if DigestValueMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getSigningCertificateDigestValueMatchConstraint(Context context);

	/**
	 * Indicates if all signing certificate reference digests match the signing certificate
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if AllCertDigestsMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
    LevelConstraint getAllSigningCertificateDigestValuesMatchConstraint(Context context);

    /**
	 * Indicates if the signing certificate reference's issuer serial matches
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if IssuerSerialMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelConstraint getSigningCertificateIssuerSerialMatchConstraint(Context context);

	/**
	 * Indicates if the referenced data is found
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if ReferenceDataExistence for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelConstraint getReferenceDataExistenceConstraint(Context context);

	/**
	 * Indicates if the referenced data is intact
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if ReferenceDataIntact for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelConstraint getReferenceDataIntactConstraint(Context context);

	/**
	 * Indicates if the manifested document is found
	 *
	 * @param context {@link Context}
	 * @return {@code LevelConstraint} if ManifestEntryObjectExistence for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getManifestEntryObjectExistenceConstraint(Context context);

	/**
	 * Indicates if the signature is intact
	 *
	 * @param context {@link Context}
	 * @return {@code SignatureDataIntact} if SignatureIntact for a given context
	 *         element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignatureIntactConstraint(Context context);

	/**
	 * Indicates if the signature is not ambiguous
	 *
	 * @param context {@link Context}
	 * @return {@code SignatureDuplicated} if SignatureDuplicated for a given context
	 *         element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignatureDuplicatedConstraint(Context context);
	
	/**
	 * This constraint checks if only one SignerInfo is present into a SignerInformationStore
	 * NOTE: applicable only for PAdES
	 * 
	 * @param context {@link Context}
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
	 *
	 * @return {@code LevelConstraint} if BestSignatureTimeBeforeExpirationDateOfSigningCertificate element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint();

	/**
	 * This constraint checks if the timestamp order is coherent
	 *
	 * @return {@code LevelConstraint} if TimestampCoherence element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getTimestampCoherenceConstraint();

	/**
	 * Returns TimestampDelay constraint if present in the policy, null otherwise
	 *
	 * @return {@code TimeConstraint} if TimestampDelay element is present
	 *                                 in the constraint file, null otherwise.
	 */
	TimeConstraint getTimestampDelayConstraint();

	/**
	 * Returns RevocationTimeAgainstBestSignatureTime constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelConstraint} if RevocationTimeAgainstBestSignatureTime element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getRevocationTimeAgainstBestSignatureTimeConstraint();

	/**
	 * Returns RevocationFreshness constraint if present in the policy, null otherwise
	 *
	 * @return {@code TimeConstraint} if RevocationFreshness element is present
	 *                                 in the constraint file, null otherwise.
	 */
	TimeConstraint getRevocationFreshnessConstraint();

	/**
	 * Returns CounterSignature constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}DiagnosticDataFacade
	 * @return {@code LevelConstraint} if CounterSignature element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getCounterSignatureConstraint(Context context);

	/**
	 * Returns SignatureFormat constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @return {@code MultiValuesConstraint} if SignatureFormat element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getSignatureFormatConstraint(Context context);

	/**
	 * Returns CertificateCountry constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificateCountry element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificateCountryConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateOrganizationName constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificateOrganizationName element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificateOrganizationNameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateOrganizationUnit constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificateOrganizationUnit element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificateOrganizationUnitConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateSurname constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificateSurname element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificateSurnameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateGivenName constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificateGivenName element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificateGivenNameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateCommonName constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificateCommonName element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificateCommonNameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificatePseudonym constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificatePseudonym element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificatePseudonymConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificatePseudoUsage constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if CertificatePseudoUsage element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getCertificatePseudoUsageConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateSerialNumber constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if CertificateSerialNumber element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getCertificateSerialNumberConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateAuthorityInfoAccessPresent constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if CertificateAuthorityInfoAccessPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getCertificateAuthorityInfoAccessPresentConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateRevocationInfoAccessPresent constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if CertificateRevocationInfoAccessPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getCertificateRevocationInfoAccessPresentConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificatePolicyIds constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesConstraint} if CertificatePolicyIds element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCertificatePolicyIdsConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateIssuedToNaturalPerson constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelConstraint} if CertificateIssuedToNaturalPerson element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getCertificateIssuedToNaturalPersonConstraint(Context context, SubContext subContext);

	/**
	 * Returns AcceptedContainerTypes constraint if present in the policy, null otherwise
	 *
	 * @return {@code MultiValuesConstraint} if AcceptedContainerTypes element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getAcceptedContainerTypesConstraint();

	/**
	 * Returns ZipCommentPresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelConstraint} if ZipCommentPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getZipCommentPresentConstraint();

	/**
	 * Returns AcceptedZipComments constraint if present in the policy, null otherwise
	 *
	 * @return {@code MultiValuesConstraint} if AcceptedZipComments element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getAcceptedZipCommentsConstraint();

	/**
	 * Returns MimeTypeFilePresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelConstraint} if MimeTypeFilePresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getMimeTypeFilePresentConstraint();

	/**
	 * Returns AcceptedMimeTypeContents constraint if present in the policy, null otherwise
	 *
	 * @return {@code MultiValuesConstraint} if AcceptedMimeTypeContents element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getAcceptedMimeTypeContentsConstraint();

	/**
	 * Returns AllFilesSigned constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelConstraint} if AllFilesSigned element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getAllFilesSignedConstraint();

	/**
	 * Returns ManifestFilePresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelConstraint} if ManifestFilePresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getManifestFilePresentConstraint();

	/**
	 * Returns SignedFilesPresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelConstraint} if SignedFilesPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getSignedFilesPresentConstraint();

	/**
	 * Returns FullScope constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelConstraint} if FullScope element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getFullScopeConstraint();

	/* Article 32 */

	/**
	 * Returns if EIDAS constraints present (qualification check shall be performed)
	 *
	 * @return TRUE if EIDAS constraint present, FALSE otherwise
	 */
	boolean isEIDASConstraintPresent();

	/**
	 * Returns TLFreshness constraint if present in the policy, null otherwise
	 *
	 * @return {@code TimeConstraint} if TLFreshness element is present
	 *                                 in the constraint file, null otherwise.
	 */
	TimeConstraint getTLFreshnessConstraint();

	/**
	 * Returns TLWellSigned constraint if present in the policy, null otherwise
	 *
	 * @return {@code TimeConstraint} if TLWellSigned element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getTLWellSignedConstraint();

	/**
	 * Returns TLNotExpired constraint if present in the policy, null otherwise
	 *
	 * @return {@code TimeConstraint} if TLNotExpired element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelConstraint getTLNotExpiredConstraint();

	/**
	 * Returns TLVersion constraint if present in the policy, null otherwise
	 *
	 * @return {@code ValueConstraint} if TLVersion element is present
	 *                                 in the constraint file, null otherwise.
	 */
	ValueConstraint getTLVersionConstraint();

	/**
	 * Returns the used validation model (default is SHELL). Alternatives are CHAIN
	 * and HYBRID
	 * 
	 * @return the validation model to be used
	 */
	Model getValidationModel();

	/**
	 * Returns the constraint used for ASiC Container validation
	 *
	 * @return {@code ContainerConstraints}
	 */
	ContainerConstraints getContainerConstraints();

	/**
	 * Returns the constraint used for Signature validation
	 *
	 * @return {@code SignatureConstraints}
	 */
	SignatureConstraints getSignatureConstraints();

	/**
	 * Returns the constraint used for Counter Signature validation
	 *
	 * @return {@code SignatureConstraints}
	 */
	SignatureConstraints getCounterSignatureConstraints();

	/**
	 * Returns the constraint used for Timestamp validation
	 *
	 * @return {@code TimestampConstraints}
	 */
	TimestampConstraints getTimestampConstraints();

	/**
	 * Returns the constraint used for Revocation validation
	 *
	 * @return {@code RevocationConstraints}
	 */
	RevocationConstraints getRevocationConstraints();

	/**
	 * Returns the constraint used for qualification validation
	 *
	 * @return {@code EIDAS}
	 */
	EIDAS getEIDASConstraints();

	/**
	 * Returns the common constraint used for cryptographic validation
	 *
	 * @return {@code CryptographicConstraint}
	 */
	CryptographicConstraint getCryptographic();

}
