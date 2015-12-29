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
package eu.europa.esig.dss.validation.policy;

import java.util.Date;
import java.util.List;

import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;
import eu.europa.esig.jaxb.policy.RevocationConstraints;
import eu.europa.esig.jaxb.policy.ValueConstraint;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. This is the base class used to implement a specific validation
 * policy
 */
public interface ValidationPolicy2 {

	public enum Context {
		MAIN_SIGNATURE,
		TIMESTAMP,
		REVOCATION
	};

	public enum SubContext {
		SIGNING_CERT,
		CA_CERTIFICATE
	};

	boolean isRevocationFreshnessToBeChecked();

	String getFormatedMaxRevocationFreshness();

	/**
	 * This function returns the maximum duration in milliseconds for which the revocation data are considered fresh.
	 *
	 * @return
	 */
	Long getMaxRevocationFreshness();

	/**
	 * This function returns the algorithm expiration date extracted from the 'constraint.xml' file. If the TAG AlgoExpirationDate is not present within the
	 * constraints {@code null} is returned.
	 *
	 * @param algorithm
	 *            algorithm (SHA1, SHA256, RSA2048...) to be checked
	 * @return expiration date or null
	 */
	Date getAlgorithmExpirationDate(String algorithm, Context context, SubContext subContext);

	/**
	 * Indicates if the signature policy should be checked. If AcceptablePolicies element is absent within the constraint file then null is returned,
	 * otherwise the list of identifiers is initialised.
	 *
	 * @return {@code LevelConstraint} if SigningTime element is present in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getSignaturePolicyConstraint();

	/**
	 * Indicates if the structural validation should be checked. If StructuralValidation element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelConstraint} if StructuralValidation element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getStructuralValidationConstraint();

	/**
	 * Indicates if the signed property: signing-time should be checked. If SigningTime element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelConstraint} if SigningTime element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningTimeConstraint();

	/**
	 * Indicates if the signed property: content-type should be checked. If ContentType element is absent within the constraint file then null is returned.
	 *
	 * @return {@code ValueConstraint} if ContentType element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentTypeConstraint();

	/**
	 * Indicates if the signed property: content-hints should be checked. If ContentHints element is absent within the constraint file then null is returned.
	 *
	 * @return {@code ValueConstraint} if ContentHints element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentHintsConstraint();

	/**
	 * Indicates if the signed property: content-identifier should be checked. If ContentIdentifier element is absent within the constraint file then null is returned.
	 *
	 * @return {@code ValueConstraint} if ContentIdentifier element is present in the constraint file, null otherwise.
	 */
	ValueConstraint getContentIdentifierConstraint();

	/**
	 * Indicates if the signed property: commitment-type-indication should be checked. If CommitmentTypeIndication element is absent within the constraint file then null is
	 * returned, otherwise the list of identifiers is initialised.
	 *
	 * @return {@code MultiValuesConstraint} if CommitmentTypeIndication element is present in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getCommitmentTypeIndicationConstraint();

	/**
	 * Indicates if the signed property: signer-location should be checked. If SignerLocation element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelConstraint} if SignerLocation element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignerLocationConstraint();

	/**
	 * Indicates if the signed property: content-time-stamp should be checked. If ContentTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelConstraint} if ContentTimeStamp element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getContentTimestampConstraint();

	/**
	 * Indicates if the signed property: content-time-stamp should be checked. If ClaimedRoles element is absent within the constraint file then null is returned.
	 *
	 * @return {@code LevelConstraint} if ClaimedRoles element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getClaimedRoleConstraint();

	/**
	 * Return the mandated signer role.
	 *
	 * @return
	 */
	List<String> getClaimedRoles();

	/**
	 * Indicates if the presence of the Signer Role is mandatory.
	 *
	 * @return
	 */
	boolean shouldCheckIfCertifiedRoleIsPresent();

	/**
	 * Return the mandated signer role.
	 *
	 * @return
	 */
	List<String> getCertifiedRoles();

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
	 * Returns the timestamp delay in milliseconds.
	 *
	 * @return
	 */
	Long getTimestampDelayTime();

	String getCertifiedRolesAttendance();

	/**
	 * This method creates the {@code SignatureCryptographicConstraint} corresponding to the context parameter. If AcceptableEncryptionAlgo is not present in the constraint file
	 * the null is returned.
	 *
	 * @param context
	 *            The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @return {@code SignatureCryptographicConstraint} if AcceptableEncryptionAlgo for a given context element is present in the constraint file, null otherwise.
	 */
	CryptographicConstraint getSignatureCryptographicConstraint(Context context);

	/**
	 * This method creates the {@code SignatureCryptographicConstraint} corresponding to the context parameter. If AcceptableEncryptionAlgo is not present in the constraint file
	 * the null is returned.
	 *
	 * @param context
	 *            The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @param subContext
	 *            the sub context of the signature cryptographic constraints: EMPTY (signature itself), SigningCertificate, CACertificate
	 * @return {@code SignatureCryptographicConstraint} if AcceptableEncryptionAlgo for a given context element is present in the constraint file, null otherwise.
	 */
	CryptographicConstraint getSignatureCryptographicConstraint( Context context,  SubContext subContext);

	/**
	 * @param context
	 * @return {@code LevelConstraint} if key-usage for a given context element is present in the constraint file, null otherwise.
	 */
	MultiValuesConstraint getSigningCertificateKeyUsageConstraint(Context context);

	/**
	 * @param context
	 * @param subContext
	 * @return {@code LevelConstraint} if Expiration for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateExpirationConstraint( Context context,  SubContext subContext);

	/**
	 * This constraint requests the presence of the trust anchor in the certificate chain.
	 *
	 * @param context
	 * @return {@code LevelConstraint} if ProspectiveCertificateChain element for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getProspectiveCertificateChainConstraint(final Context context);

	/**
	 * @param context
	 * @param subContext
	 * @return {@code LevelConstraint} if Signature for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getCertificateSignatureConstraint(Context context, SubContext subContext);

	/**
	 * @param context
	 * @return {@code LevelConstraint} if RevocationDataAvailable for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getRevocationDataAvailableConstraint(Context context, SubContext subContext);

	/**
	 * @param context
	 * @return {@code LevelConstraint} if RevocationDataIsTrusted for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getRevocationDataIsTrustedConstraint(Context context, SubContext subContext);

	/**
	 * @param context
	 * @return {@code LevelConstraint} if RevocationDataFreshness for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getRevocationDataFreshnessConstraint(Context context, SubContext subContext);

	/**
	 * @return {@code LevelConstraint} if Revoked for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateRevokedConstraint(Context context, SubContext subContext);

	/**
	 * @return {@code LevelConstraint} if OnHold for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateOnHoldConstraint(Context context, SubContext subContext);

	/**
	 * @return {@code LevelConstraint} if the TSLValidity for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateTSLValidityConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if TSLStatus for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateTSLStatusConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if the TSLValidity for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateTSLStatusAndValidityConstraint(Context context);

	/**
	 * @param context
	 *            of the certificate: main signature, timestamp, revocation data
	 * @return {@code LevelConstraint} if Revoked for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getIntermediateCertificateRevokedConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if CertificateChain for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getChainConstraint();

	/**
	 * @return {@code LevelConstraint} if Qualification for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateQualificationConstraint();

	/**
	 * Indicates if the end user certificate used in validating the signature is mandated to be supported by a secure
	 * signature creation device (SSCD) as defined in Directive 1999/93/EC [9].
	 *
	 * @return {@code LevelConstraint} if SupportedBySSCD for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateSupportedBySSCDConstraint();

	/**
	 * @return {@code LevelConstraint} if IssuedToLegalPerson for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateIssuedToLegalPersonConstraint();

	/**
	 * @return {@code LevelConstraint} if Recognition for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateRecognitionConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if Signed for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateSignedConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if SigningCertificateAttribute for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateAttributePresentConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if DigestValuePresent for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateDigestValuePresentConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if DigestValueMatch for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateDigestValueMatchConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if IssuerSerialMatch for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSigningCertificateIssuerSerialMatchConstraint(Context context);

	/**
	 * @return {@code LevelConstraint} if ReferenceDataExistence for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getReferenceDataExistenceConstraint();

	/**
	 * @return {@code ReferenceDataIntact} if ReferenceDataIntact for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getReferenceDataIntactConstraint();

	/**
	 * @return {@code ReferenceDataIntact} if SignatureIntact for a given context element is present in the constraint file, null otherwise.
	 */
	LevelConstraint getSignatureIntactConstraint();

	BasicValidationProcessValidConstraint getBasicValidationProcessConclusionConstraint();

	LevelConstraint getMessageImprintDataFoundConstraint();

	LevelConstraint getMessageImprintDataIntactConstraint();

	/**
	 * This constraint is always executed!
	 *
	 * @return
	 */
	TimestampValidationProcessValidConstraint getTimestampValidationProcessConstraint();

	LevelConstraint getRevocationTimeConstraint();

	LevelConstraint getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint();

	LevelConstraint getSigningCertificateValidityAtBestSignatureTimeConstraint();

	LevelConstraint getAlgorithmReliableAtBestSignatureTimeConstraint();

	LevelConstraint getTimestampCoherenceConstraint();

	/**
	 * This constraint has only two levels: FAIL, or NOTHING
	 *
	 * @return
	 */
	LevelConstraint getTimestampDelaySigningTimePropertyConstraint();

	RevocationConstraints getRevocationConstraint();

	LevelConstraint getCounterSignatureConstraint();

}
