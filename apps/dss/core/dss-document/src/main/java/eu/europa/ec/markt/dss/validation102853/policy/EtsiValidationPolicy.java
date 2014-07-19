/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.policy;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. It
 * adds the functions to direct access to the file data. It is the implementation of the ETSI 102853 standard.
 *
 * @author bielecro
 */
public class EtsiValidationPolicy extends ValidationPolicy {

	protected static final String TRUE = "true";
	protected static final String FALSE = "false";

	private long maxRevocationFreshnessString;

	private String maxRevocationFreshnessUnit;

	private Long maxRevocationFreshness;

	private Long timestampDelayTime;
	private Map<String, Date> algorithmExpirationDate = new HashMap<String, Date>();

	public EtsiValidationPolicy(Document document) {

		super(document);
	}

	/**
	 * @return
	 */
	public boolean isRevocationFreshnessToBeChecked() {

		return null != getElement("/ConstraintsParameters/Revocation/RevocationFreshness/");
	}

	public String getFormatedMaxRevocationFreshness() {

		if (maxRevocationFreshness == null) {

			getMaxRevocationFreshness();
		}
		return maxRevocationFreshnessString + " " + maxRevocationFreshnessUnit;
	}

	/**
	 * This function returns the maximum duration in milliseconds for which the revocation data are considered fresh.
	 *
	 * @return
	 */
	public Long getMaxRevocationFreshness() {

		if (maxRevocationFreshness == null) {

			maxRevocationFreshness = Long.MAX_VALUE;

			final XmlDom revocationFreshness = getElement("/ConstraintsParameters/Revocation/RevocationFreshness");
			if (revocationFreshness != null) {

				maxRevocationFreshnessString = getLongValue("/ConstraintsParameters/Revocation/RevocationFreshness/text()");
				maxRevocationFreshnessUnit = getValue("/ConstraintsParameters/Revocation/RevocationFreshness/@Unit");
				maxRevocationFreshness = RuleUtils.convertDuration(maxRevocationFreshnessUnit, "MILLISECONDS", maxRevocationFreshnessString);
				if (maxRevocationFreshness == 0) {

					maxRevocationFreshness = Long.MAX_VALUE;
				}
			}
		}
		return maxRevocationFreshness;
	}

	/**
	 * This function returns the algorithm expiration date extracted from the 'constraint.xml' file. If the TAG AlgoExpirationDate is not present within the
	 * constraints {@code null} is returned.
	 *
	 * @param algorithm algorithm (SHA1, SHA256, RSA2048...) to be checked
	 * @return expiration date or null
	 */
	public Date getAlgorithmExpirationDate(final String algorithm) {

		Date date = algorithmExpirationDate.get(algorithm);
		if (date == null) {

			final XmlDom algoExpirationDateDom = getElement("/ConstraintsParameters/Timestamp/Cryptographic/AlgoExpirationDate");
			if (algoExpirationDateDom == null) {

				return null;
			}
			String expirationDateFormat = algoExpirationDateDom.getValue("./@Format");
			if (expirationDateFormat.isEmpty()) {

				expirationDateFormat = "yyyy-MM-dd";
			}

			final String expirationDateString = algoExpirationDateDom.getValue("./Algo[@Name='%s']/text()", algorithm);
			if (expirationDateString.isEmpty()) {

				throw new DSSException(String.format("The the expiration date is not defined for '%s' algorithm!", algorithm));
			}
			date = RuleUtils.parseDate(expirationDateFormat, expirationDateString);
			algorithmExpirationDate.put(algorithm, date);
		}
		return date;
	}

	/**
	 * Indicates if the signature policy should be checked. If AcceptablePolicies element is absent within the constraint file then null is returned,
	 * otherwise the list of identifiers is initialised.
	 *
	 * @return {@code Constraint} if SigningTime element is present in the constraint file, null otherwise.
	 */
	public SignaturePolicyConstraint getSignaturePolicyConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/AcceptablePolicies/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final SignaturePolicyConstraint constraint = new SignaturePolicyConstraint(level);

			final List<XmlDom> policyList = getElements("/ConstraintsParameters/MainSignature/AcceptablePolicies/Id");
			final List<String> identifierList = XmlDom.convertToStringList(policyList);
			constraint.setIdentifiers(identifierList);
			constraint.setExpectedValue(identifierList.toString());
			return constraint;
		}
		return null;
	}

	/**
	 * Indicates if the signed property: signing-time should be checked. If SigningTime element is absent within the constraint file then null is returned.
	 *
	 * @return {@code Constraint} if SigningTime element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/SigningTime";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * Indicates if the signed property: content-type should be checked. If ContentType element is absent within the constraint file then null is returned.
	 *
	 * @return {@code Constraint} if ContentType element is present in the constraint file, null otherwise.
	 */
	public Constraint getContentTypeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentType";
		return getBasicConstraint(XP_ROOT, true);
	}


	/**
	 * Indicates if the signed property: content-hints should be checked. If ContentHints element is absent within the constraint file then null is returned.
	 *
	 * @return {@code Constraint} if ContentHints element is present in the constraint file, null otherwise.
	 */
	public Constraint getContentHintsConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentHints";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * Indicates if the signed property: content-identifier should be checked. If ContentIdentifier element is absent within the constraint file then null is returned.
	 *
	 * @return {@code Constraint} if ContentIdentifier element is present in the constraint file, null otherwise.
	 */
	public Constraint getContentIdentifierConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentIdentifier";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * Indicates if the signed property: commitment-type-indication should be checked. If CommitmentTypeIndication element is absent within the constraint file then null is
	 * returned, otherwise the list of identifiers is initialised.
	 *
	 * @return {@code Constraint} if CommitmentTypeIndication element is present in the constraint file, null otherwise.
	 */
	public Constraint getCommitmentTypeIndicationConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CommitmentTypeIndication/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> commitmentTypeIndications = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CommitmentTypeIndication/Identifier");
			final List<String> identifierList = XmlDom.convertToStringList(commitmentTypeIndications);
			constraint.setExpectedValue(identifierList.toString());
			constraint.setIdentifiers(identifierList);
			return constraint;
		}
		return null;
	}

	/**
	 * Indicates if the signed property: signer-location should be checked. If SignerLocation element is absent within the constraint file then null is returned.
	 *
	 * @return {@code Constraint} if SignerLocation element is present in the constraint file, null otherwise.
	 */
	public Constraint getSignerLocationConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/SignerLocation/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			return constraint;
		}
		return null;
	}

	/**
	 * Indicates if the signed property: content-time-stamp should be checked. If ContentTimeStamp element is absent within the constraint file then null is returned.
	 *
	 * @return {@code Constraint} if ContentTimeStamp element is present in the constraint file, null otherwise.
	 */
	public Constraint getContentTimeStampConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentTimeStamp/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			return constraint;
		}
		return null;
	}

	/**
	 * Indicates if the signed property: content-time-stamp should be checked. If ClaimedRoles element is absent within the constraint file then null is returned.
	 *
	 * @return {@code Constraint} if ClaimedRoles element is present in the constraint file, null otherwise.
	 */
	public Constraint getClaimedRoleConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> claimedRoles = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/Role");
			final List<String> claimedRoleList = XmlDom.convertToStringList(claimedRoles);
			constraint.setExpectedValue(claimedRoleList.toString());
			constraint.setIdentifiers(claimedRoleList);
			return constraint;
		}
		return null;
	}

	/**
	 * Return the mandated signer role.
	 *
	 * @return
	 */
	public List<String> getClaimedRoles() {

		final List<XmlDom> list = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/Role");
		final List<String> claimedRoles = XmlDom.convertToStringList(list);
		return claimedRoles;
	}

	/**
	 * Indicates if the presence of the Signer Role is mandatory.
	 *
	 * @return
	 */
	public boolean shouldCheckIfCertifiedRoleIsPresent() {

		final long count = getCountValue("count(/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CertifiedRoles/Role)");
		return count > 0;
	}

	/**
	 * Return the mandated signer role.
	 *
	 * @return
	 */
	public List<String> getCertifiedRoles() {

		final List<XmlDom> list = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CertifiedRoles/Role");
		final List<String> claimedRoles = XmlDom.convertToStringList(list);
		return claimedRoles;
	}

	/**
	 * Returns the name of the policy.
	 *
	 * @return
	 */
	public String getPolicyName() {

		final String policy = getValue("/ConstraintsParameters/@Name");
		return policy;
	}

	/**
	 * Returns the policy description.
	 *
	 * @return
	 */
	public String getPolicyDescription() {

		final String description = getValue("/ConstraintsParameters/Description/text()");
		return description;
	}

	/**
	 * Returns the timestamp delay in milliseconds.
	 *
	 * @return
	 */
	public Long getTimestampDelayTime() {

		if (timestampDelayTime == null) {

			final XmlDom timestampDelayPresent = getElement("/ConstraintsParameters/Timestamp/TimestampDelay");
			if (timestampDelayPresent == null) {

				return null;
			}
			final long timestampDelay = getLongValue("/ConstraintsParameters/Timestamp/TimestampDelay/text()");
			final String timestampUnit = getValue("/ConstraintsParameters/Timestamp/TimestampDelay/@Unit");
			timestampDelayTime = RuleUtils.convertDuration(timestampUnit, "MILLISECONDS", timestampDelay);
		}
		return timestampDelayTime;
	}

	public String getCertifiedRolesAttendance() {

		String attendance = getValue("ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/@Attendance");
		return attendance;
	}

	/**
	 * This method creates the {@code SignatureCryptographicConstraint} corresponding to the context parameter. If AcceptableEncryptionAlgo is not present in the constraint file
	 * the null is returned.
	 *
	 * @param context The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @return {@code SignatureCryptographicConstraint} if AcceptableEncryptionAlgo for a given context element is present in the constraint file, null otherwise.
	 */
	public SignatureCryptographicConstraint getSignatureCryptographicConstraint(final String context) {

		final String rootXPathQuery = String.format("/ConstraintsParameters/%s/Cryptographic", context);
		return getSignatureCryptographicConstraint_(rootXPathQuery, context, null);
	}

	/**
	 * This method creates the {@code SignatureCryptographicConstraint} corresponding to the context parameter. If AcceptableEncryptionAlgo is not present in the constraint file
	 * the null is returned.
	 *
	 * @param context    The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @param subContext the sub context of the signature cryptographic constraints: EMPTY (signature itself), SigningCertificate, CACertificate
	 * @return {@code SignatureCryptographicConstraint} if AcceptableEncryptionAlgo for a given context element is present in the constraint file, null otherwise.
	 */
	public SignatureCryptographicConstraint getSignatureCryptographicConstraint(final String context, final String subContext) {

		final String rootXPathQuery = String.format("/ConstraintsParameters/%s/%s/Cryptographic", context, subContext);
		return getSignatureCryptographicConstraint_(rootXPathQuery, context, subContext);
	}

	/**
	 * This method creates the {@code SignatureCryptographicConstraint} corresponding to the context parameter. If AcceptableEncryptionAlgo is not present in the constraint file
	 * the null is returned.
	 *
	 * @param rootXPathQuery The context of the signature cryptographic constraints is included within the XPath query.
	 * @param context        The context of the signature cryptographic constraints: MainSignature, Timestamp, Revocation
	 * @param subContext     the sub context of the signature cryptographic constraints: EMPTY (signature itself), SigningCertificate, CACertificate
	 * @return {@code SignatureCryptographicConstraint} if AcceptableEncryptionAlgo for a given context element is present in the constraint file, null otherwise.
	 */
	private SignatureCryptographicConstraint getSignatureCryptographicConstraint_(final String rootXPathQuery, final String context, final String subContext) {

		final String level = getValue(rootXPathQuery + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final SignatureCryptographicConstraint constraint = new SignatureCryptographicConstraint(level, context, subContext);

			final List<XmlDom> encryptionAlgoList = getElements(rootXPathQuery + "/AcceptableEncryptionAlgo/Algo");
			final List<String> encryptionAlgoStringList = XmlDom.convertToStringList(encryptionAlgoList);
			constraint.setEncryptionAlgorithms(encryptionAlgoStringList);

			final List<XmlDom> digestAlgoList = getElements(rootXPathQuery + "/AcceptableDigestAlgo/Algo");
			final List<String> digestAlgoStringList = XmlDom.convertToStringList(digestAlgoList);
			constraint.setDigestAlgorithms(digestAlgoStringList);

			final List<XmlDom> miniPublicKeySizeList = getElements(rootXPathQuery + "/MiniPublicKeySize/Algo");
			final Map<String, String> miniPublicKeySizeStringMap = XmlDom.convertToStringMap(miniPublicKeySizeList, SIZE);
			constraint.setMinimumPublicKeySizes(miniPublicKeySizeStringMap);

			final List<XmlDom> algoExpirationDateList = getElements("/ConstraintsParameters/Cryptographic/AlgoExpirationDate/Algo");
			final Map<String, Date> algoExpirationDateStringMap = XmlDom.convertToStringDateMap(algoExpirationDateList, DATE);
			constraint.setAlgorithmExpirationDates(algoExpirationDateStringMap);

			return constraint;
		}
		return null;
	}

	/**
	 * @param context
	 * @param subContext
	 * @return {@code Constraint} if Expiration for a given context element is present in the constraint file, null otherwise.
	 */
	public CertificateExpirationConstraint getSigningCertificateExpirationConstraint(final String context, final String subContext) {

		final String level = getValue(String.format("/ConstraintsParameters/%s/%s/Expiration/@Level", context, subContext));
		if (DSSUtils.isNotBlank(level)) {

			final CertificateExpirationConstraint constraint = new CertificateExpirationConstraint(level);
			return constraint;
		}
		return null;
	}

	/**
	 * This constraint requests the presence of the trust anchor in the certificate chain.
	 *
	 * @param context
	 * @return {@code Constraint} if ProspectiveCertificateChain element for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getProspectiveCertificateChainConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/ProspectiveCertificateChain", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @param context
	 * @param subContext
	 * @return {@code Constraint} if Signature for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getCertificateSignatureConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/Signature", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @param context
	 * @return {@code Constraint} if RevocationDataAvailable for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getRevocationDataAvailableConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/RevocationDataAvailable", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @param context
	 * @return {@code Constraint} if RevocationDataIsTrusted for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getRevocationDataIsTrustedConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/RevocationDataIsTrusted", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @param context
	 * @return {@code Constraint} if RevocationDataFreshness for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getRevocationDataFreshnessConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/RevocationDataFreshness", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if Revoked for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateRevokedConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/Revoked", context, subContext);
		return getBasicConstraint(XP_ROOT, false);
	}

	/**
	 * @return {@code Constraint} if OnHold for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateOnHoldConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/OnHold", context, subContext);
		return getBasicConstraint(XP_ROOT, false);
	}

	/**
	 * @return {@code Constraint} if the TSLValidity for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateTSLValidityConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/TSLValidity", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if TSLStatus for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateTSLStatusConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/TSLStatus", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if the TSLValidity for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateTSLStatusAndValidityConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/TSLStatusAndValidity", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @param context of the certificate: main signature, timestamp, revocation data
	 * @return {@code Constraint} if Revoked for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getIntermediateCertificateRevokedConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/CACertificate/Revoked", context);
		return getBasicConstraint(XP_ROOT, false);
	}

	/**
	 * @return {@code Constraint} if CertificateChain for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getChainConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/CertificateChain/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			return constraint;
		}
		return null;
	}

	/**
	 * @return {@code Constraint} if Qualification for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateQualificationConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SigningCertificate/Qualification";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * Indicates if the end user certificate used in validating the signature is mandated to be supported by a secure
	 * signature creation device (SSCD) as defined in Directive 1999/93/EC [9].
	 *
	 * @return {@code Constraint} if SupportedBySSCD for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateSupportedBySSCDConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SigningCertificate/SupportedBySSCD";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if IssuedToLegalPerson for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateIssuedToLegalPersonConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SigningCertificate/IssuedToLegalPerson";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if Recognition for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateRecognitionConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/Recognition", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if Signed for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateSignedConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/Signed", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if SigningCertificateAttribute for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateAttributePresentConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/AttributePresent", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if DigestValuePresent for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateDigestValuePresentConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/DigestValuePresent", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if DigestValueMatch for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateDigestValueMatchConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/DigestValueMatch", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if IssuerSerialMatch for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSigningCertificateIssuerSerialMatchConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/IssuerSerialMatch", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code Constraint} if ReferenceDataExistence for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getReferenceDataExistenceConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/ReferenceDataExistence";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code ReferenceDataIntact} if ReferenceDataIntact for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getReferenceDataIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/ReferenceDataIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * @return {@code ReferenceDataIntact} if SignatureIntact for a given context element is present in the constraint file, null otherwise.
	 */
	public Constraint getSignatureIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SignatureIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * This method returns the "basic" constraint able to handle simple (empty/not empty), boolean value and identifiers list.
	 *
	 * @param XP_ROOT              is the root part of the XPath query use to retrieve the constraint description.
	 * @param defaultExpectedValue true or false
	 * @return
	 */
	private Constraint getBasicConstraint(final String XP_ROOT, final boolean defaultExpectedValue) {

		final String level = getValue(XP_ROOT + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			String expectedValue = getValue(XP_ROOT + "/text()");
			if (DSSUtils.isBlank(expectedValue)) {
				expectedValue = defaultExpectedValue ? TRUE : FALSE;
			}
			constraint.setExpectedValue(expectedValue);
			return constraint;
		}
		return null;
	}

	public BasicValidationProcessValidConstraint getBasicValidationProcessConclusionConstraint() {

		final BasicValidationProcessValidConstraint constraint = new BasicValidationProcessValidConstraint("FAIL");
		constraint.setExpectedValue(TRUE);
		return constraint;
	}

	public Constraint getMessageImprintDataFoundConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/MessageImprintDataFound";
		return getBasicConstraint(XP_ROOT, true);
	}

	public Constraint getMessageImprintDataIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/MessageImprintDataIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	/**
	 * This constraint is always executed!
	 *
	 * @return
	 */
	public TimestampValidationProcessValidConstraint getTimestampValidationProcessConstraint() {

		final TimestampValidationProcessValidConstraint constraint = new TimestampValidationProcessValidConstraint("FAIL");
		constraint.setExpectedValue(TRUE);
		return constraint;
	}

	public Constraint getRevocationTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/RevocationTimeAgainstBestSignatureTime";
		return getBasicConstraint(XP_ROOT, true);
	}

	public Constraint getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/BestSignatureTimeBeforeIssuanceDateOfSigningCertificate";
		return getBasicConstraint(XP_ROOT, true);
	}

	public Constraint getSigningCertificateValidityAtBestSignatureTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/SigningCertificateValidityAtBestSignatureTime";
		return getBasicConstraint(XP_ROOT, true);
	}

	public Constraint getAlgorithmReliableAtBestSignatureTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/AlgorithmReliableAtBestSignatureTime";
		return getBasicConstraint(XP_ROOT, true);
	}


	public Constraint getTimestampCoherenceConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/Coherence";
		return getBasicConstraint(XP_ROOT, true);
	}


	/**
	 * This constraint is has only two levels: FAIL, or NOTHING
	 *
	 * @return
	 */
	public Constraint getTimestampDelaySigningTimePropertyConstraint() {

		final Long timestampDelay = getTimestampDelayTime();
		if (timestampDelay != null && timestampDelay > 0) {

			final Constraint constraint = new Constraint("FAIL");
			constraint.setExpectedValue(TRUE);
			return constraint;
		}
		return null;
	}
}

