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
package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.ValidationModel;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. This
 * is the base class used to implement a
 * specific validation policy
 */
public interface ValidationPolicy {

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
	 * Indicates if the signature policy should be checked. If AcceptablePolicies element is absent within the
	 * constraint file then null is returned, otherwise
	 * the list of identifiers is initialised.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SigningTime element is present in the constraint file, null otherwise.
	 */
	MultiValuesRule getSignaturePolicyConstraint(Context context);

	/**
	 * Indicates if the signature policy validation should be processed.
	 * If SignaturePolicyIdentifier found, but not relevant SignaturePolicy is retrieved, the check fails.
	 * 
	 * @param context {@link Context}
	 * @return {@link LevelRule} if SignaturePolicy shall be identified
	 */
	LevelRule getSignaturePolicyIdentifiedConstraint(Context context);

	/**
	 * Indicates if a SignaturePolicyStore unsigned attribute, containing a used policy binaries,
	 * presence shall be checked
	 * 
	 * @param context {@link Context}
	 * @return {@link LevelRule} if SignaturePolicyStore presence shall be checked
	 */
	LevelRule getSignaturePolicyStorePresentConstraint(Context context);

	/**
	 * Indicates if digest present in a SignaturePolicyIdentifier shall match to the extracted policy content
	 * 
	 * @param context {@link Context}
	 * @return {@link LevelRule} if SignaturePolicyIdentifier digest shall match
	 */
	LevelRule getSignaturePolicyPolicyHashValid(Context context);

	/**
	 * Indicates if the structural validation should be checked. If StructuralValidation element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if StructuralValidation element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelRule getStructuralValidationConstraint(Context context);

	/**
	 * Indicates if the Signing Certificate attribute should be checked against the certificate chain.
	 * If SigningCertificateRefersCertificateChain element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SigningCertificateRefersCertificateChain element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getSigningCertificateRefersCertificateChainConstraint(Context context);

	/**
	 * Indicates if the whole certificate chain is covered by the Signing Certificate attribute.
	 * If ReferencesToAllCertificateChainPresent element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ReferencesToAllCertificateChainPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getReferencesToAllCertificateChainPresentConstraint(Context context);

	/**
	 * Checks if a used DigestAlgorithm in signing-certificate-reference creation matches
	 * the corresponding cryptographic constraint
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SigningCertificateDigestAlgorithm for a given context element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getSigningCertificateDigestAlgorithmConstraint(Context context);

	/**
	 * Indicates if the signed property: signing-time should be checked. If SigningTime element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SigningTime element is present in the constraint file, null otherwise.
	 */
	LevelRule getSigningDurationRule(Context context);

	/**
	 * Indicates if the signed property: content-type should be checked. If ContentType element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code ValueRule} if ContentType element is present in the constraint file, null otherwise.
	 */
	ValueRule getContentTypeConstraint(Context context);

	/**
	 * Indicates if the signed property: content-hints should be checked. If ContentHints element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code ValueRule} if ContentHints element is present in the constraint file, null otherwise.
	 */
	ValueRule getContentHintsConstraint(Context context);

	/**
	 * Indicates if the signed property: content-identifier should be checked. If ContentIdentifier element is absent
	 * within the constraint file then null is
	 * returned.
	 *
	 * @param context {@link Context}
	 * @return {@code ValueRule} if ContentIdentifier element is present in the constraint file, null otherwise.
	 */
	ValueRule getContentIdentifierConstraint(Context context);

	/**
	 * Indicates if the signed property: message-digest (for CAdES) or SignedProperties (for XAdES) should be checked.
	 * If the relative element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if message-digests/SignedProperties element is present in the constraint file, null otherwise.
	 */
	LevelRule getMessageDigestOrSignedPropertiesConstraint(Context context);

	/**
	 * This constraint checks whether a JWA signature has a valid elliptic curve key size
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if EllipticCurveKeySize element is present in the constraint file, null otherwise.
	 */
	LevelRule getEllipticCurveKeySizeConstraint(Context context);

	/**
	 * Indicates if the signed property: commitment-type-indication should be checked. If CommitmentTypeIndication
	 * element is absent within the constraint file
	 * then null is returned, otherwise the list of identifiers is initialised.
	 *
	 * @param context {@link Context}
	 * @return {@code MultiValuesRule} if CommitmentTypeIndication element is present in the constraint file, null
	 *         otherwise.
	 */
	MultiValuesRule getCommitmentTypeIndicationConstraint(Context context);

	/**
	 * Indicates if the signed property: signer-location should be checked. If SignerLocation element is absent within
	 * the constraint file then null is
	 * returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SignerLocation element is present in the constraint file, null otherwise.
	 */
	LevelRule getSignerLocationConstraint(Context context);

	/**
	 * Indicates if the signed property: content-time-stamp should be checked.
	 * If ContentTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ContentTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getContentTimeStampConstraint(Context context);

	/**
	 * Indicates if the signed property: content-time-stamp message-imprint should be checked.
	 * If ContentTimeStampMessageImprint element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ContentTimeStampMessageImprint element is present in the constraint file,
	 *                                 null otherwise.
	 */
	LevelRule getContentTimeStampMessageImprintConstraint(Context context);

	/**
	 * Indicates if the unsigned property: claimed-role should be checked. If ClaimedRoles element is absent within the
	 * constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code MultiValuesRule} if ClaimedRoles element is present in the constraint file, null otherwise.
	 */
	MultiValuesRule getClaimedRoleConstraint(Context context);

	/**
	 * Return the mandated signer role.
	 *
	 * @param context {@link Context}
	 * @return {@link MultiValuesRule}
	 */
	MultiValuesRule getCertifiedRolesConstraint(Context context);

	/**
	 * This method creates the {@code SignatureCryptographicRules} corresponding to the context parameter. If
	 * AcceptableEncryptionAlgo is not present in
	 * the constraint file the null is returned.
	 *
	 * @param context
	 *            The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @return {@code SignatureCryptographicRules} if AcceptableEncryptionAlgo for a given context element is
	 *         present in the constraint file, null
	 *         otherwise.
	 */
	CryptographicRules getSignatureCryptographicConstraint(Context context);

	/**
	 * This method creates the {@code SignatureCryptographicRules} corresponding to the context parameter. If
	 * AcceptableEncryptionAlgo is not present in
	 * the constraint file the null is returned.
	 *
	 * @param context
	 *            The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @param subContext
	 *            the sub context of the signature cryptographic constraints: EMPTY (signature itself),
	 *            SigningCertificate, CACertificate
	 * @return {@code SignatureCryptographicRules} if AcceptableEncryptionAlgo for a given context element is
	 *         present in the constraint file, null
	 *         otherwise.
	 */
	CryptographicRules getCertificateCryptographicConstraint(Context context, SubContext subContext);

	/**
	 * This method returns cryptographic constraints for validation of Evidence Record
	 *
	 * @return {@link CryptographicRules}
	 */
	CryptographicRules getEvidenceRecordCryptographicConstraint();

	/**
	 * Returns certificate CA constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if CA for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificateCAConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate IssuerName constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if IssuerName for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificateIssuerNameConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate MaxPathLength constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if MaxPathLength for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificateMaxPathLengthConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate key usage constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if key-usage for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	MultiValuesRule getCertificateKeyUsageConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate extended key usage constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if extended key-usage for a given context element is present in the constraint file,
	 *                                 null otherwise.
	 */
	MultiValuesRule getCertificateExtendedKeyUsageConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate PolicyTree constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if PolicyTree for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificatePolicyTreeConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate NameConstraints constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if NameConstraints for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificateNameConstraintsConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate NoRevAvail constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if NoRevAvail for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificateNoRevAvailConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate supported critical extensions constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if SupportedCriticalExtensions constraint for a given context element is present
	 * 								   in the constraint file,null otherwise.
	 */
	MultiValuesRule getCertificateSupportedCriticalExtensionsConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate forbidden extensions constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if ForbiddenExtensions constraint for a given context element is present
	 * 								   in the constraint file,null otherwise.
	 */
	MultiValuesRule getCertificateForbiddenExtensionsConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's validity range constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if NotExpired constraint for a given certificate context is present
	 * 			in the constraint file, null otherwise.
	 */
	LevelRule getCertificateNotExpiredConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's sunset date constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if SunsetDate constraint for a given certificate context is present
	 * 			in the constraint file, null otherwise.
	 */
	LevelRule getCertificateSunsetDateConstraint(Context context, SubContext subContext);

	/**
	 * This constraint requests the presence of the trust anchor in the certificate chain.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ProspectiveCertificateChain element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelRule getProspectiveCertificateChainConstraint(Context context);

	/**
	 * Returns certificate's signature constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if Signature for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelRule getCertificateSignatureConstraint(Context context, SubContext subContext);

	/**
	 * The method returns UnknownStatus constraint
	 * 
	 * @return {@link LevelRule}
	 */
	LevelRule getUnknownStatusConstraint();

	/**
	 * The method returns ThisUpdatePresent constraint
	 *
	 * @return {@link LevelRule}
	 */
	LevelRule getThisUpdatePresentConstraint();

	/**
	 * The method returns RevocationIssuerKnown constraint
	 *
	 * @return {@link LevelRule}
	 */
	LevelRule getRevocationIssuerKnownConstraint();

	/**
	 * The method returns RevocationIssuerValidAtProductionTime constraint
	 *
	 * @return {@link LevelRule}
	 */
	LevelRule getRevocationIssuerValidAtProductionTimeConstraint();

	/**
	 * The method returns RevocationIssuerKnowsCertificate constraint
	 *
	 * @return {@link LevelRule}
	 */
	LevelRule getRevocationAfterCertificateIssuanceConstraint();

	/**
	 * The method returns RevocationIssuerHasInformationAboutCertificate constraint
	 *
	 * @return {@link LevelRule}
	 */
	LevelRule getRevocationHasInformationAboutCertificateConstraint();

	/**
	 * The method returns OCSPResponderIdMatch constraint
	 *
	 * @return {@link LevelRule}
	 */
	LevelRule getOCSPResponseResponderIdMatchConstraint();

	/**
	 * The method returns OCSPCertHashPresent constraint
	 * 
	 * @return {@link LevelRule}
	 */
	LevelRule getOCSPResponseCertHashPresentConstraint();

	/**
	 * The method returns OCSPCertHashMatch constraint
	 * 
	 * @return {@link LevelRule}
	 */
	LevelRule getOCSPResponseCertHashMatchConstraint();

	/**
	 * The method returns SelfIssuedOCSP constraint
	 * 
	 * @return {@link LevelRule}
	 */
	LevelRule getSelfIssuedOCSPConstraint();

	/**
	 * Returns revocation data available constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if RevocationDataAvailable for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getRevocationDataAvailableConstraint(Context context, SubContext subContext);

	/**
	 * Returns acceptable revocation data available constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if AcceptableRevocationDataFound for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getAcceptableRevocationDataFoundConstraint(Context context, SubContext subContext);

	/**
	 * Returns CRL's nextUpdate present constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if CRLNextUpdatePresent for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getCRLNextUpdatePresentConstraint(Context context, SubContext subContext);

	/**
	 * Returns OCSP's nextUpdate present constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if OCSPNextUpdatePresent for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getOCSPNextUpdatePresentConstraint(Context context, SubContext subContext);

	/**
	 * Returns revocation data's freshness constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code DurationRule} if RevocationFreshness for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	DurationRule getRevocationFreshnessConstraint(Context context, SubContext subContext);

	/**
	 * Returns revocation data's freshness for nextUpdate check constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if RevocationFreshnessNextUpdate for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getRevocationFreshnessNextUpdateConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's not revoked constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if Revoked for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelRule getCertificateNotRevokedConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's not onHold constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if OnHold for a given context element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelRule getCertificateNotOnHoldConstraint(Context context, SubContext subContext);

	/**
	 * Returns revocation issuer's validity range constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if RevocationIssuerNotExpired constraint for a given certificate context is present
	 * 			in the constraint file, null otherwise.
	 */
	LevelRule getRevocationIssuerNotExpiredConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's not self-signed constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if not self-signed for a given context element is present in the constraint file,
	 *                                 null otherwise.
	 */
	LevelRule getCertificateNotSelfSignedConstraint(Context context, SubContext subContext);

	/**
	 * Returns certificate's self-signed constraint
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if self-signed for a given context element is present in the constraint file,
	 *                                 null otherwise.
	 */
	LevelRule getCertificateSelfSignedConstraint(Context context, SubContext subContext);

	/**
	 * Returns trusted service type identifier constraint
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if trusted service type identifier for a given context element is present in
	 *                                 the constraint file, null otherwise.
	 */
	MultiValuesRule getTrustServiceTypeIdentifierConstraint(Context context);

	/**
	 * Returns trusted service status constraint
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if trusted service status for a given context element is present in
	 *                                 the constraint file, null otherwise.
	 */
	MultiValuesRule getTrustServiceStatusConstraint(Context context);

	/**
	 * Returns CertificatePolicyIds constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificatePolicyIds element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificatePolicyIdsConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the CertificatePolicyIds declare the certificate as qualified.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if PolicyQualificationIds for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	LevelRule getCertificatePolicyQualificationIdsConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the CertificatePolicyIds mandate the certificate as to be supported by
	 * a secure signature creation device (QSCD).
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if PolicySupportedByQSCDIds for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificatePolicySupportedByQSCDIdsConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is QC Compliant.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if QcCompliance for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getCertificateQCComplianceConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the allowed currency used to specify certificate's QCLimitValue statement.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code NumericValueRule} if QcTransactionLimitCurrency for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	ValueRule getCertificateQcEuLimitValueCurrencyConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the minimal allowed QcEuLimitValue transaction limit for which the end user certificate used
	 * for the signature can be used.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code NumericValueRule} if MinQcTransactionLimit for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	NumericValueRule getCertificateMinQcEuLimitValueConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the minimal allowed QC retention period for material information relevant to the use of
	 * the end user certificate used for the signature.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code NumericValueRule} if MinQcRetentionPeriod for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	NumericValueRule getCertificateMinQcEuRetentionPeriodConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is mandated to be supported by a secure
	 * signature creation device (QSCD).
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if QcSSCD for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	LevelRule getCertificateQcSSCDConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the location or set of locations of PKI Disclosure Statements.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} the the location or set of locations of PKI Disclosure Statements
	 */
	MultiValuesRule getCertificateQcEuPDSLocationConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the certificate is claimed as a certificate of a particular type.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} the types that the certificate is claimed to be of
	 */
	MultiValuesRule getCertificateQcTypeConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the country or set of countries under the legislation of which the certificate is issued as a
	 * qualified certificate is present.
	 *
	 * NOTE: in order to verify the EU compliance, the value shall be empty (no QcCCLegislation is allowed)
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} the country or set of countries under the legislation of which
	 * 		the certificate is issued as a qualified certificate
	 */
	MultiValuesRule getCertificateQcCCLegislationConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is issued to a natural person.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if IssuedToNaturalPerson for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelRule getCertificateIssuedToNaturalPersonConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if the end user certificate used in validating the signature is issued to a legal person.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if IssuedToLegalPerson for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelRule getCertificateIssuedToLegalPersonConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the certificate's QCStatement contains an acceptable semantics identifier.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if SemanticsIdentifier for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateSemanticsIdentifierConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the acceptable QC PS2D roles for the certificate used for a signature.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} the set of acceptable QC PS2D roles
	 */
	MultiValuesRule getCertificatePS2DQcTypeRolesOfPSPConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the acceptable QC PS2D names for the certificate used for a signature.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} the set of acceptable QC PS2D names
	 */
	MultiValuesRule getCertificatePS2DQcCompetentAuthorityNameConstraint(Context context, SubContext subContext);

	/**
	 * Indicates the acceptable QC PS2D ids for the certificate used for a signature.
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} the set of acceptable QC PS2D ids
	 */
	MultiValuesRule getCertificatePS2DQcCompetentAuthorityIdConstraint(Context context, SubContext subContext);

	/**
	 * Indicates if signing-certificate has been identified.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if Recognition for a given context element is present in the constraint file,
	 *         null otherwise.
	 */
	LevelRule getSigningCertificateRecognitionConstraint(Context context);

	/**
	 * Indicates if the signing certificate attribute is present
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SigningCertificateAttribute for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelRule getSigningCertificateAttributePresentConstraint(Context context);

	/**
	 * Indicates if the signing certificate is not ambiguously determines
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if UnicitySigningCertificate for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getUnicitySigningCertificateAttributeConstraint(Context context);

	/**
	 * Indicates if the signing certificate reference's digest value is present
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if DigestValuePresent for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelRule getSigningCertificateDigestValuePresentConstraint(Context context);

	/**
	 * Indicates if the signing certificate reference's digest value matches
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if DigestValueMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelRule getSigningCertificateDigestValueMatchConstraint(Context context);

    /**
	 * Indicates if the signing certificate reference's issuer serial matches
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if IssuerSerialMatch for a given context element is present in the constraint
	 *         file, null otherwise.
	 */
	LevelRule getSigningCertificateIssuerSerialMatchConstraint(Context context);

	/**
	 * Indicates if the 'kid' (key identifier) header parameter is present within the protected header of the signature
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if KeyIdentifierPresent for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	LevelRule getKeyIdentifierPresent(Context context);

	/**
	 * Indicates if the value of 'kid' (key identifier) header parameter matches the signing-certificate
	 * used to create the signature
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if KeyIdentifierMatch for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	LevelRule getKeyIdentifierMatch(Context context);

	/**
	 * Indicates if the referenced data is found
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ReferenceDataExistence for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelRule getReferenceDataExistenceConstraint(Context context);

	/**
	 * Indicates if the referenced data is intact
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ReferenceDataIntact for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelRule getReferenceDataIntactConstraint(Context context);

	/**
	 * Indicates if the referenced document names match the manifest entry references
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ReferenceDataNameMatch for a given context element is present in the
	 *         constraint file, null otherwise.
	 */
	LevelRule getReferenceDataNameMatchConstraint(Context context);

	/**
	 * Indicates if the manifested document is found
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ManifestEntryObjectExistence for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getManifestEntryObjectExistenceConstraint(Context context);

	/**
	 * Indicates if the manifested document is intact
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ManifestEntryObjectIntact for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getManifestEntryObjectIntactConstraint(Context context);

	/**
	 * Indicates if all manifest entries have been found
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ManifestEntryObjectGroup for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getManifestEntryObjectGroupConstraint(Context context);

	/**
	 * Indicates if names of all matching documents match to the manifest entry names
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ManifestEntryNameMatch for a given
	 *         context element is present in the constraint file, null otherwise.
	 */
	LevelRule getManifestEntryNameMatchConstraint(Context context);

	/**
	 * Indicates if the signature is intact
	 *
	 * @param context {@link Context}
	 * @return {@code SignatureDataIntact} if SignatureIntact for a given context
	 *         element is present in the constraint file, null otherwise.
	 */
	LevelRule getSignatureIntactConstraint(Context context);

	/**
	 * Indicates if the signature is not ambiguous
	 *
	 * @param context {@link Context}
	 * @return {@code SignatureDuplicated} if SignatureDuplicated for a given context
	 *         element is present in the constraint file, null otherwise.
	 */
	LevelRule getSignatureDuplicatedConstraint(Context context);
	
	/**
	 * This constraint checks if only one SignerInfo is present into a SignerInformationStore
	 * NOTE: applicable only for PAdES
	 * 
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SignerInformationStore element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelRule getSignerInformationStoreConstraint(Context context);

	/**
	 * This constraint checks if ByteRange dictionary is valid
	 * NOTE: applicable only for PAdES
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ByteRange element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelRule getByteRangeConstraint(Context context);

	/**
	 * This constraint checks if ByteRange does not collide with other signature byte ranges
	 * NOTE: applicable only for PAdES
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ByteRangeCollision element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelRule getByteRangeCollisionConstraint(Context context);

	/**
	 * This constraint checks if ByteRange is valid for all signatures and document timestamps within PDF
	 * NOTE: applicable only for PAdES
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ByteRangeAllDocument element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelRule getByteRangeAllDocumentConstraint(Context context);

	/**
	 * This constraint checks if signature dictionary is consistent across PDF revisions.
	 * NOTE: applicable only for PAdES
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if PdfSignatureDictionary element for a given context element is present in
	 *         the constraint file, null otherwise.
	 */
	LevelRule getPdfSignatureDictionaryConstraint(Context context);
	
	/**
	 * Indicates if a PDF page difference check should be proceeded. If PdfPageDifference element is absent within
	 * the constraint file then null is returned.
	 * 
	 * @param context {@link Context}
	 * @return {@code LevelRule} if PdfPageDifference element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelRule getPdfPageDifferenceConstraint(Context context);
	
	/**
	 * Indicates if a PDF annotation overlapping check should be proceeded. If PdfAnnotationOverlap element is absent within
	 * the constraint file then null is returned.
	 * 
	 * @param context {@link Context}
	 * @return {@code LevelRule} if PdfAnnotationOverlap element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelRule getPdfAnnotationOverlapConstraint(Context context);
	
	/**
	 * Indicates if a PDF visual difference check should be proceeded. If PdfVisualDifference element is absent within
	 * the constraint file then null is returned.
	 * 
	 * @param context {@link Context}
	 * @return {@code LevelRule} if PdfVisualDifference element is present in the constraint file, null
	 *         otherwise.
	 */
	LevelRule getPdfVisualDifferenceConstraint(Context context);

	/**
	 * This constraint checks if a document contains changes after a signature,
	 * against permission rules identified within a /DocMDP dictionary
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if DocMDP element is present in the constraint file, null otherwise.
	 */
	LevelRule getDocMDPConstraint(Context context);

	/**
	 * This constraint checks if a document contains changes after a signature,
	 * against permission rules identified within a /FieldMDP dictionary
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if FieldMDP element is present in the constraint file, null otherwise.
	 */
	LevelRule getFieldMDPConstraint(Context context);

	/**
	 * This constraint checks if a document contains changes after a signature,
	 * against permission rules identified within a /SigFieldLock dictionary
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SigFieldLock element is present in the constraint file, null otherwise.
	 */
	LevelRule getSigFieldLockConstraint(Context context);

	/**
	 * This constraint checks whether a PDF document contains form fill or signing modifications
	 * after the current signature's revisions
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if FormFillChanges element is present in the constraint file, null otherwise.
	 */
	LevelRule getFormFillChangesConstraint(Context context);

	/**
	 * This constraint checks whether a PDF document contains annotation creation, modification or deletion modifications
	 * after the current signature's revisions
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if AnnotationChanges element is present in the constraint file, null otherwise.
	 */
	LevelRule getAnnotationChangesConstraint(Context context);

	/**
	 * This constraint checks whether a PDF document contains undefined object modifications
	 * after the current signature's revisions
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if UndefinedChanges element is present in the constraint file, null otherwise.
	 */
	LevelRule getUndefinedChangesConstraint(Context context);

	/**
	 * This constraint checks if the certificate is not expired on best-signature-time
	 *
	 * @return {@code LevelRule} if BestSignatureTimeBeforeExpirationDateOfSigningCertificate element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint();

	/**
	 * This constraint checks if the timestamp order is coherent
	 *
	 * @return {@code LevelRule} if TimestampCoherence element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getTimestampCoherenceConstraint();

	/**
	 * Returns TimestampDelay constraint if present in the policy, null otherwise
	 *
	 * @return {@code DurationRule} if TimestampDelay element is present
	 *                                 in the constraint file, null otherwise.
	 */
	DurationRule getTimestampDelayConstraint();

	/**
	 * Returns whether the time-stamp is valid (passed either basic signature validation process or past signature validation).
	 * If TimestampValid element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelRule} if TimestampValid element is present in the constraint file, null otherwise.
	 */
	LevelRule getTimestampValidConstraint();

	/**
	 * Indicates if the timestamp's TSTInfo.tsa field is present
	 *
	 * @return {@code LevelRule} if TSAGeneralNamePresent for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	LevelRule getTimestampTSAGeneralNamePresent();

	/**
	 * Indicates if the timestamp's TSTInfo.tsa field's value matches the timestamp's issuer distinguishing name
	 * when present
	 *
	 * @return {@code LevelRule} if TSAGeneralNameContentMatch for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	LevelRule getTimestampTSAGeneralNameContentMatch();

	/**
	 * Indicates if the timestamp's TSTInfo.tsa field's value and order match the timestamp's issuer distinguishing name
	 * when present
	 *
	 * @return {@code LevelRule} if TSAGeneralNameOrderMatch for a given context element is present
	 *         in the constraint file, null otherwise.
	 */
	LevelRule getTimestampTSAGeneralNameOrderMatch();

	/**
	 * Returns timestamp AtsHashIndex constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if AtsHashIndex element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getAtsHashIndexConstraint();

	/**
	 * Returns timestamp ContainerSignedAndTimestampedFilesCovered constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if ContainerSignedAndTimestampedFilesCovered element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getTimestampContainerSignedAndTimestampedFilesCoveredConstraint();

	/**
	 * Returns RevocationTimeAgainstBestSignatureTime constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if RevocationTimeAgainstBestSignatureTime element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getRevocationTimeAgainstBestSignatureDurationRule();

	/**
	 * Returns whether the evidence record is valid (passed a complete evidence record validation process).
	 * If EvidenceRecordValid element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelRule} if EvidenceRecordValid element is present in the constraint file, null otherwise.
	 */
	LevelRule getEvidenceRecordValidConstraint();

	/**
	 * Returns DataObjectExistence constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if DataObjectExistence element is present
	 */
	LevelRule getEvidenceRecordDataObjectExistenceConstraint();

	/**
	 * Returns DataObjectIntact constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if DataObjectIntact element is present
	 */
	LevelRule getEvidenceRecordDataObjectIntactConstraint();

	/**
	 * Returns DataObjectFound constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if DataObjectFound element is present
	 */
	LevelRule getEvidenceRecordDataObjectFoundConstraint();

	/**
	 * Returns DataObjectGroup constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if DataObjectGroup element is present
	 */
	LevelRule getEvidenceRecordDataObjectGroupConstraint();

	/**
	 * Returns SignedFilesCovered constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if SignedFilesCovered element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getEvidenceRecordSignedFilesCoveredConstraint();

	/**
	 * Returns evidence record ContainerSignedAndTimestampedFilesCovered constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if ContainerSignedAndTimestampedFilesCovered element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getEvidenceRecordContainerSignedAndTimestampedFilesCoveredConstraint();

	/**
	 * Returns HashTreeRenewal constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if HashTreeRenewal element is present
	 */
	LevelRule getEvidenceRecordHashTreeRenewalConstraint();

	/**
	 * Returns CounterSignature constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}DiagnosticDataFacade
	 * @return {@code LevelRule} if CounterSignature element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getCounterSignatureConstraint(Context context);

	/**
	 * Indicates if the presence of unsigned property: signature-time-stamp should be checked.
	 * If SignatureTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if SignatureTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getSignatureTimeStampConstraint(Context context);

	/**
	 * Indicates if the presence of unsigned property: validation data timestamp should be checked.
	 * If ValidationDataTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ValidationDataTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getValidationDataTimeStampConstraint(Context context);

	/**
	 * Indicates if the presence of unsigned property: validation data references only timestamp should be checked.
	 * If ValidationDataRefsOnlyTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ValidationDataRefsOnlyTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getValidationDataRefsOnlyTimeStampConstraint(Context context);

	/**
	 * Indicates if the presence of unsigned property: archive-time-stamp should be checked.
	 * If ArchiveTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if ArchiveTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getArchiveTimeStampConstraint(Context context);

	/**
	 * Indicates if the presence of unsigned property: document timestamp should be checked.
	 * If DocumentTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if DocumentTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getDocumentTimeStampConstraint(Context context);

	/**
	 * Indicates if the presence of unsigned property: signature-time-stamp or document timestamp
	 * If TLevelTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if TLevelTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getTLevelTimeStampConstraint(Context context);

	/**
	 * Indicates if the presence of unsigned property: archive-time-stamp or document timestamp covering the validation data
	 * If LTALevelTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @param context {@link Context}
	 * @return {@code LevelRule} if LTALevelTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelRule getLTALevelTimeStampConstraint(Context context);

	/**
	 * Returns SignatureFormat constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @return {@code MultiValuesRule} if SignatureFormat element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getSignatureFormatConstraint(Context context);

	/**
	 * Returns CertificateCountry constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateCountry element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateCountryConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateLocality constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateLocality element is present
	 *                                       in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateLocalityConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateState constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateState element is present
	 *                                       in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateStateConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateOrganizationIdentifier constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateOrganizationIdentifier element is present
	 *                                       in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateOrganizationIdentifierConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateOrganizationName constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateOrganizationName element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateOrganizationNameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateOrganizationUnit constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateOrganizationUnit element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateOrganizationUnitConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateSurname constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateSurname element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateSurnameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateGivenName constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateGivenName element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateGivenNameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateCommonName constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateCommonName element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateCommonNameConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificatePseudonym constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificatePseudonym element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificatePseudonymConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificatePseudoUsage constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if CertificatePseudoUsage element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getCertificatePseudoUsageConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateTitle constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateTitle element is present
	 *                                       in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateTitleConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateEmail constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code MultiValuesRule} if CertificateEmail element is present
	 *                                       in the constraint file, null otherwise.
	 */
	MultiValuesRule getCertificateEmailConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateSerialNumber constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if CertificateSerialNumber element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getCertificateSerialNumberConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateAuthorityInfoAccessPresent constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if CertificateAuthorityInfoAccessPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getCertificateAuthorityInfoAccessPresentConstraint(Context context, SubContext subContext);

	/**
	 * Returns RevocationDataSkip constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if RevocationDataSkip element is present
	 *                                 in the constraint file, null otherwise.
	 */
	CertificateApplicabilityRule getRevocationDataSkipConstraint(Context context, SubContext subContext);

	/**
	 * Returns CertificateRevocationInfoAccessPresent constraint if present in the policy, null otherwise
	 *
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @return {@code LevelRule} if CertificateRevocationInfoAccessPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getCertificateRevocationInfoAccessPresentConstraint(Context context, SubContext subContext);

	/**
	 * Returns AcceptedContainerTypes constraint if present in the policy, null otherwise
	 *
	 * @return {@code MultiValuesRule} if AcceptedContainerTypes element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getAcceptedContainerTypesConstraint();

	/**
	 * Returns ZipCommentPresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if ZipCommentPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getZipCommentPresentConstraint();

	/**
	 * Returns AcceptedZipComments constraint if present in the policy, null otherwise
	 *
	 * @return {@code MultiValuesRule} if AcceptedZipComments element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getAcceptedZipCommentsConstraint();

	/**
	 * Returns MimeTypeFilePresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if MimeTypeFilePresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getMimeTypeFilePresentConstraint();

	/**
	 * Returns AcceptedMimeTypeContents constraint if present in the policy, null otherwise
	 *
	 * @return {@code MultiValuesRule} if AcceptedMimeTypeContents element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getAcceptedMimeTypeContentsConstraint();

	/**
	 * Returns ManifestFilePresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if ManifestFilePresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getManifestFilePresentConstraint();

	/**
	 * Returns SignedFilesPresent constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if SignedFilesPresent element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getSignedFilesPresentConstraint();

	/**
	 * Returns AllFilesSigned constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if AllFilesSigned element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getAllFilesSignedConstraint();

	/**
	 * Returns FullScope constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if FullScope element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getFullScopeConstraint();

	/**
	 * Returns AcceptablePDFAProfiles constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if AcceptablePDFAProfiles element is present
	 *                                 in the constraint file, null otherwise.
	 */
	MultiValuesRule getAcceptablePDFAProfilesConstraint();

	/**
	 * Returns PDFACompliant constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if PDFACompliant element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getPDFACompliantConstraint();

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
	 * @return {@code LevelRule} if TLFreshness element is present
	 *                                 in the constraint file, null otherwise.
	 */
	DurationRule getTLFreshnessConstraint();

	/**
	 * Returns TLWellSigned constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if TLWellSigned element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getTLWellSignedConstraint();

	/**
	 * Returns TLNotExpired constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if TLNotExpired element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getTLNotExpiredConstraint();

	/**
	 * Returns TLVersion constraint if present in the policy, null otherwise
	 *
	 * @return {@code MultiValuesRule} if TLVersion element is present
	 *                                       in the constraint file, null otherwise.
	 */
	MultiValuesRule getTLVersionConstraint();

	/**
	 * Returns TLStructure constraint if present in the policy, null otherwise
	 *
	 * @return {@code LevelRule} if TLStructure element is present
	 *                                 in the constraint file, null otherwise.
	 */
	LevelRule getTLStructureConstraint();

	/**
	 * Returns the used validation model (default is SHELL). Alternatives are CHAIN and HYBRID
	 * 
	 * @return the validation model to be used
	 */
	ValidationModel getValidationModel();

//	/**
//	 * Returns the constraint used for Signature validation
//	 *
//	 * @return {@code SignatureConstraints}
//	 */
//	SignatureConstraints getSignatureConstraints();
//
//	/**
//	 * Returns the constraint used for Counter Signature validation
//	 *
//	 * @return {@code SignatureConstraints}
//	 */
//	SignatureConstraints getCounterSignatureConstraints();
//
//	/**
//	 * Returns the constraint used for Timestamp validation
//	 *
//	 * @return {@code TimestampConstraints}
//	 */
//	TimestampConstraints getTimestampConstraints();
//
//	/**
//	 * Returns the constraint used for Revocation validation
//	 *
//	 * @return {@code RevocationConstraints}
//	 */
//	RevocationConstraints getRevocationConstraints();
//
//	/**
//	 * Returns the constraint used for Evidence Record validation
//	 *
//	 * @return {@link EvidenceRecordConstraints}
//	 */
//	EvidenceRecordConstraints getEvidenceRecordConstraints();
//
//	/**
//	 * Returns the constraint used for ASiC Container validation
//	 *
//	 * @return {@code ContainerConstraints}
//	 */
//	ContainerConstraints getContainerConstraints();
//
//	/**
//	 * Returns the constraint used for ASiC Container validation
//	 *
//	 * @return {@code ContainerConstraints}
//	 */
//	PDFAConstraints getPDFAConstraints();
//
//	/**
//	 * Returns the constraint used for qualification validation
//	 *
//	 * @return {@code EIDAS}
//	 */
//	EIDAS getEIDASConstraints();
//
//	/**
//	 * Returns the common constraint used for cryptographic validation
//	 *
//	 * @return {@code CryptographicRules}
//	 */
//	CryptographicRules getCryptographic();

}
