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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. It
 * adds the functions to direct access to the file data. It is the implementation of the ETSI 102853 standard.
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

	@Override
	public boolean isRevocationFreshnessToBeChecked() {

		return null != getElement("/ConstraintsParameters/Revocation/RevocationFreshness/");
	}

	@Override
	public String getFormatedMaxRevocationFreshness() {

		if (maxRevocationFreshness == null) {

			getMaxRevocationFreshness();
		}
		return maxRevocationFreshnessString + " " + maxRevocationFreshnessUnit;
	}

	@Override
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

	@Override
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
			date = DSSUtils.parseDate(expirationDateFormat, expirationDateString);
			algorithmExpirationDate.put(algorithm, date);
		}
		return date;
	}

	@Override
	public SignaturePolicyConstraint getSignaturePolicyConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/AcceptablePolicies/@Level");
		if (StringUtils.isNotBlank(level)) {

			final SignaturePolicyConstraint constraint = new SignaturePolicyConstraint(level);

			final List<XmlDom> policyList = getElements("/ConstraintsParameters/MainSignature/AcceptablePolicies/Id");
			final List<String> identifierList = XmlDom.convertToStringList(policyList);
			constraint.setIdentifiers(identifierList);
			constraint.setExpectedValue(identifierList.toString());
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getStructuralValidationConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/StructuralValidation";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/SigningTime";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getContentTypeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentType";
		return getBasicConstraint(XP_ROOT, true);
	}


	@Override
	public Constraint getContentHintsConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentHints";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getContentIdentifierConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentIdentifier";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getCommitmentTypeIndicationConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CommitmentTypeIndication/@Level");
		if (StringUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> commitmentTypeIndications = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CommitmentTypeIndication/Identifier");
			final List<String> identifierList = XmlDom.convertToStringList(commitmentTypeIndications);
			constraint.setExpectedValue(identifierList.toString());
			constraint.setIdentifiers(identifierList);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getSignerLocationConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/SignerLocation/@Level");
		if (StringUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getContentTimestampPresenceConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentTimestamp/@Level");
		if (StringUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getClaimedRoleConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/@Level");
		if (StringUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> claimedRoles = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/Role");
			final List<String> claimedRoleList = XmlDom.convertToStringList(claimedRoles);
			constraint.setExpectedValue(claimedRoleList.toString());
			constraint.setIdentifiers(claimedRoleList);
			return constraint;
		}
		return null;
	}

	@Override
	public List<String> getClaimedRoles() {

		final List<XmlDom> list = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/Role");
		final List<String> claimedRoles = XmlDom.convertToStringList(list);
		return claimedRoles;
	}

	@Override
	public boolean shouldCheckIfCertifiedRoleIsPresent() {

		final long count = getCountValue("count(/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CertifiedRoles/Role)");
		return count > 0;
	}

	@Override
	public List<String> getCertifiedRoles() {

		final List<XmlDom> list = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CertifiedRoles/Role");
		final List<String> claimedRoles = XmlDom.convertToStringList(list);
		return claimedRoles;
	}

	@Override
	public String getPolicyName() {

		final String policy = getValue("/ConstraintsParameters/@Name");
		return policy;
	}

	@Override
	public String getPolicyDescription() {

		final String description = getValue("/ConstraintsParameters/Description/text()");
		return description;
	}

	@Override
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

	@Override
	public String getCertifiedRolesAttendance() {

		String attendance = getValue("ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/@Attendance");
		return attendance;
	}

	@Override
	public SignatureCryptographicConstraint getSignatureCryptographicConstraint(final String context) {

		final String rootXPathQuery = String.format("/ConstraintsParameters/%s/Cryptographic", context);
		return getSignatureCryptographicConstraint_(rootXPathQuery, context, null);
	}

	@Override
	public SignatureCryptographicConstraint getSignatureCryptographicConstraint(final String context, final String subContext) {

		final String rootXPathQuery = String.format("/ConstraintsParameters/%s/%s/Cryptographic", context, subContext);
		return getSignatureCryptographicConstraint_(rootXPathQuery, context, subContext);
	}

	@Override
	protected SignatureCryptographicConstraint getSignatureCryptographicConstraint_(final String rootXPathQuery, final String context, final String subContext) {

		final String level = getValue(rootXPathQuery + "/@Level");
		if (StringUtils.isNotBlank(level)) {

			final SignatureCryptographicConstraint constraint = new SignatureCryptographicConstraint(level, context, subContext);

			final List<XmlDom> encryptionAlgoList = getElements(rootXPathQuery + "/AcceptableEncryptionAlgo/Algo");
			final List<String> encryptionAlgoStringList = XmlDom.convertToStringList(encryptionAlgoList);
			constraint.setEncryptionAlgorithms(encryptionAlgoStringList);

			final List<XmlDom> digestAlgoList = getElements(rootXPathQuery + "/AcceptableDigestAlgo/Algo");
			final List<String> digestAlgoStringList = XmlDom.convertToStringList(digestAlgoList);
			constraint.setDigestAlgorithms(digestAlgoStringList);

			final List<XmlDom> miniPublicKeySizeList = getElements(rootXPathQuery + "/MiniPublicKeySize/Algo");
			final Map<String, String> miniPublicKeySizeStringMap = XmlDom.convertToStringMap(miniPublicKeySizeList, AttributeName.SIZE);
			constraint.setMinimumPublicKeySizes(miniPublicKeySizeStringMap);

			final List<XmlDom> algoExpirationDateList = getElements("/ConstraintsParameters/Cryptographic/AlgoExpirationDate/Algo");
			final Map<String, Date> algoExpirationDateStringMap = XmlDom.convertToStringDateMap(algoExpirationDateList, AttributeName.DATE);
			constraint.setAlgorithmExpirationDates(algoExpirationDateStringMap);

			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getSigningCertificateKeyUsageConstraint(final String context) {

		final String level = getValue("/ConstraintsParameters/%s/SigningCertificate/KeyUsage/@Level", context);
		if (StringUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> keyUsages = getElements("/ConstraintsParameters/%s/SigningCertificate/KeyUsage/Identifier", context);
			final List<String> identifierList = XmlDom.convertToStringList(keyUsages);
			constraint.setExpectedValue(identifierList.toString());
			constraint.setIdentifiers(identifierList);
			return constraint;
		}
		return null;
	}

	@Override
	public CertificateExpirationConstraint getSigningCertificateExpirationConstraint(final String context, final String subContext) {

		final String level = getValue(String.format("/ConstraintsParameters/%s/%s/Expiration/@Level", context, subContext));
		if (StringUtils.isNotBlank(level)) {

			final CertificateExpirationConstraint constraint = new CertificateExpirationConstraint(level);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getProspectiveCertificateChainConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/ProspectiveCertificateChain", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getCertificateSignatureConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/Signature", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getRevocationDataAvailableConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/RevocationDataAvailable", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getRevocationDataIsTrustedConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/RevocationDataIsTrusted", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getRevocationDataFreshnessConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/RevocationDataFreshness", context, subContext);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateRevokedConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/Revoked", context, subContext);
		return getBasicConstraint(XP_ROOT, false);
	}

	@Override
	public Constraint getSigningCertificateOnHoldConstraint(final String context, final String subContext) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/%s/OnHold", context, subContext);
		return getBasicConstraint(XP_ROOT, false);
	}

	@Override
	public Constraint getSigningCertificateTSLValidityConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/TSLValidity", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateTSLStatusConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/TSLStatus", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateTSLStatusAndValidityConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/TSLStatusAndValidity", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getIntermediateCertificateRevokedConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/CACertificate/Revoked", context);
		return getBasicConstraint(XP_ROOT, false);
	}

	@Override
	public Constraint getChainConstraint() {

		final String level = getValue("/ConstraintsParameters/MainSignature/CertificateChain/@Level");
		if (StringUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getSigningCertificateQualificationConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SigningCertificate/Qualification";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateSupportedBySSCDConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SigningCertificate/SupportedBySSCD";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateIssuedToLegalPersonConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SigningCertificate/IssuedToLegalPerson";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateRecognitionConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/Recognition", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateSignedConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/Signed", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateAttributePresentConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/AttributePresent", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateDigestValuePresentConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/DigestValuePresent", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateDigestValueMatchConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/DigestValueMatch", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateIssuerSerialMatchConstraint(final String context) {

		final String XP_ROOT = String.format("/ConstraintsParameters/%s/SigningCertificate/IssuerSerialMatch", context);
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getReferenceDataExistenceConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/ReferenceDataExistence";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getReferenceDataIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/ReferenceDataIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSignatureIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/SignatureIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	protected Constraint getBasicConstraint(final String XP_ROOT, final boolean defaultExpectedValue) {

		final String level = getValue(XP_ROOT + "/@Level");
		if (StringUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			String expectedValue = getValue(XP_ROOT + "/text()");
			if (StringUtils.isBlank(expectedValue)) {
				expectedValue = defaultExpectedValue ? TRUE : FALSE;
			}
			constraint.setExpectedValue(expectedValue);
			return constraint;
		}
		return null;
	}

	@Override
	public BasicValidationProcessValidConstraint getBasicValidationProcessConclusionConstraint() {

		final BasicValidationProcessValidConstraint constraint = new BasicValidationProcessValidConstraint("FAIL");
		constraint.setExpectedValue(TRUE);
		return constraint;
	}

	@Override
	public Constraint getMessageImprintDataFoundConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/MessageImprintDataFound";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getMessageImprintDataIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/MessageImprintDataIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public TimestampValidationProcessValidConstraint getTimestampValidationProcessConstraint() {

		final TimestampValidationProcessValidConstraint constraint = new TimestampValidationProcessValidConstraint("FAIL");
		constraint.setExpectedValue(TRUE);
		return constraint;
	}

	@Override
	public Constraint getRevocationTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/RevocationTimeAgainstBestSignatureTime";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/BestSignatureTimeBeforeIssuanceDateOfSigningCertificate";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getSigningCertificateValidityAtBestSignatureTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/SigningCertificateValidityAtBestSignatureTime";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getAlgorithmReliableAtBestSignatureTimeConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/AlgorithmReliableAtBestSignatureTime";
		return getBasicConstraint(XP_ROOT, true);
	}


	@Override
	public Constraint getTimestampCoherenceConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/Timestamp/Coherence";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getTimestampDelaySigningTimePropertyConstraint() {

		final Long timestampDelay = getTimestampDelayTime();
		if ((timestampDelay != null) && (timestampDelay > 0)) {

			final Constraint constraint = new Constraint("FAIL");
			constraint.setExpectedValue(TRUE);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getContentTimestampImprintIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentTimestamp/MessageImprintDataIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getContentTimestampImprintFoundConstraint() {
		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentTimestamp/MessageImprintDataFound";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getCounterSignatureReferenceDataExistenceConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedUnsignedQProperties/CounterSignature/ReferenceDataExistence";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getCounterSignatureReferenceDataIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedUnsignedQProperties/CounterSignature/ReferenceDataIntact";
		return getBasicConstraint(XP_ROOT, true);
	}

	@Override
	public Constraint getCounterSignatureIntactConstraint() {

		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedUnsignedQProperties/CounterSignature/SignatureIntact";
		return getBasicConstraint(XP_ROOT, true);
	}
}

