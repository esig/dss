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

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DateUtils;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.AlgoExpirationDate;
import eu.europa.esig.jaxb.policy.CertificateConstraints;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;
import eu.europa.esig.jaxb.policy.RevocationConstraints;
import eu.europa.esig.jaxb.policy.SignatureConstraints;
import eu.europa.esig.jaxb.policy.SignedAttributesConstraints;
import eu.europa.esig.jaxb.policy.TimeConstraint;
import eu.europa.esig.jaxb.policy.TimeUnit;
import eu.europa.esig.jaxb.policy.TimestampConstraints;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. It
 * adds the functions to direct access to the file data. It is the implementation of the ETSI 102853 standard.
 */
public class EtsiValidationPolicy2 implements ValidationPolicy2 {

	private static final Logger logger = LoggerFactory.getLogger(EtsiValidationPolicy2.class);

	private ConstraintsParameters policy;

	public EtsiValidationPolicy2(ConstraintsParameters policy) {
		this.policy = policy;
	}

	@Override
	public boolean isRevocationFreshnessToBeChecked() {
		RevocationConstraints revocation = policy.getRevocation();
		if (revocation != null) {
			return revocation.getRevocationFreshness() != null;
		}
		return false;
	}

	@Override
	public String getFormatedMaxRevocationFreshness() {
		return getMaxRevocationFreshness() + " " + TimeUnit.MILLISECONDS;
	}

	@Override
	public Long getMaxRevocationFreshness() {
		RevocationConstraints revocation = policy.getRevocation();
		if (revocation != null) {
			TimeConstraint revocationFreshness = revocation.getRevocationFreshness();
			if (revocationFreshness != null) {
				Long maxRevocationFreshness = RuleUtils.convertDuration(revocationFreshness.getUnit(), TimeUnit.MILLISECONDS, revocationFreshness.getValue());
				if (maxRevocationFreshness == 0) {
					maxRevocationFreshness = Long.MAX_VALUE;
				}
				return maxRevocationFreshness;
			}
		}
		return Long.MAX_VALUE;
	}

	@Override
	public RevocationConstraints getRevocationConstraint() {
		return policy.getRevocation();
	}

	@Override
	public Date getAlgorithmExpirationDate(final String algorithm, Context context, SubContext subContext) {
		CryptographicConstraint signatureCryptographicConstraint = getSignatureCryptographicConstraint(context, subContext);
		if (signatureCryptographicConstraint != null) {
			return extractExpirationDate(algorithm, signatureCryptographicConstraint);
		}
		signatureCryptographicConstraint = getSignatureCryptographicConstraint(Context.MAIN_SIGNATURE, SubContext.SIGNING_CERT);
		if (signatureCryptographicConstraint != null) {
			return extractExpirationDate(algorithm, signatureCryptographicConstraint);
		}
		return null;
	}

	private Date extractExpirationDate(final String algorithm, CryptographicConstraint signatureCryptographicConstraint) {
		AlgoExpirationDate algoExpirationDate = signatureCryptographicConstraint.getAlgoExpirationDate();
		String dateFormat = "yyyy-MM-dd";
		if (algoExpirationDate != null) {
			if (StringUtils.isNotEmpty(algoExpirationDate.getFormat())) {
				dateFormat = algoExpirationDate.getFormat();
			}
			List<Algo> algos = algoExpirationDate.getAlgo();
			String foundExpirationDate = null;
			for (Algo algo : algos) {
				if (StringUtils.equalsIgnoreCase(algo.getValue(), algorithm)) {
					foundExpirationDate = algo.getDate();
				}
			}
			if (StringUtils.isNotEmpty(foundExpirationDate)) {
				return DateUtils.parseDate(dateFormat, foundExpirationDate);
			}
		}
		return null;
	}

	@Override
	public MultiValuesConstraint getSignaturePolicyConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			return mainSignature.getAcceptablePolicies();
		}
		return null;
	}

	@Override
	public LevelConstraint getStructuralValidationConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			return mainSignature.getStructuralValidation();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningTimeConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			SignedAttributesConstraints mandatedSignedQProperties = mainSignature.getMandatedSignedQProperties();
			if (mandatedSignedQProperties != null) {
				return mandatedSignedQProperties.getSigningTime();
			}
		}
		return null;
	}

	@Override
	public LevelConstraint getContentTypeConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			SignedAttributesConstraints mandatedSignedQProperties = mainSignature.getMandatedSignedQProperties();
			if (mandatedSignedQProperties != null) {
				return mandatedSignedQProperties.getContentType();
			}
		}
		return null;
	}

	@Override
	public LevelConstraint getContentHintsConstraint() {
		// TODO ?
		//		final String XP_ROOT = "/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentHints";
		//		return getBasicConstraint(XP_ROOT, true);
		return null;
	}

	@Override
	public LevelConstraint getContentIdentifierConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			SignedAttributesConstraints mandatedSignedQProperties = mainSignature.getMandatedSignedQProperties();
			if (mandatedSignedQProperties != null) {
				return mandatedSignedQProperties.getContentIdentifier();
			}
		}
		return null;
	}

	@Override
	public LevelConstraint getCommitmentTypeIndicationConstraint() {
		// TODO
		//		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CommitmentTypeIndication/@Level");
		//		if (StringUtils.isNotBlank(level)) {
		//
		//			final Constraint constraint = new Constraint(level);
		//			final List<XmlDom> commitmentTypeIndications = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CommitmentTypeIndication/Identifier");
		//			final List<String> identifierList = XmlDom.convertToStringList(commitmentTypeIndications);
		//			constraint.setExpectedValue(identifierList.toString());
		//			constraint.setIdentifiers(identifierList);
		//			return constraint;
		//		}
		return null;
	}

	@Override
	public LevelConstraint getSignerLocationConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			SignedAttributesConstraints mandatedSignedQProperties = mainSignature.getMandatedSignedQProperties();
			if (mandatedSignedQProperties != null) {
				return mandatedSignedQProperties.getSignerLocation();
			}
		}
		return null;
	}

	@Override
	public LevelConstraint getContentTimestampPresenceConstraint() {
		//	TODO desynchro
		//		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ContentTimestamp/@Level");
		//		if (StringUtils.isNotBlank(level)) {
		//
		//			final Constraint constraint = new Constraint(level);
		//			return constraint;
		//		}
		return null;
	}

	@Override
	public LevelConstraint getClaimedRoleConstraint() {
		//	TODO
		//		final String level = getValue("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/@Level");
		//		if (StringUtils.isNotBlank(level)) {
		//
		//			final Constraint constraint = new Constraint(level);
		//			final List<XmlDom> claimedRoles = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/Role");
		//			final List<String> claimedRoleList = XmlDom.convertToStringList(claimedRoles);
		//			constraint.setExpectedValue(claimedRoleList.toString());
		//			constraint.setIdentifiers(claimedRoleList);
		//			return constraint;
		//		}
		return null;
	}

	@Override
	public List<String> getClaimedRoles() {
		// TODO ?
		//		final List<XmlDom> list = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/Role");
		//		final List<String> claimedRoles = XmlDom.convertToStringList(list);
		//		return claimedRoles;
		return Collections.emptyList();
	}

	@Override
	public boolean shouldCheckIfCertifiedRoleIsPresent() {
		// TODO ?
		//		final long count = getCountValue("count(/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CertifiedRoles/Role)");
		//		return count > 0;
		return false;
	}

	@Override
	public List<String> getCertifiedRoles() {
		// TODO ?
		//		final List<XmlDom> list = getElements("/ConstraintsParameters/MainSignature/MandatedSignedQProperties/CertifiedRoles/Role");
		//		final List<String> claimedRoles = XmlDom.convertToStringList(list);
		//		return claimedRoles;
		return Collections.emptyList();
	}

	@Override
	public String getPolicyName() {
		return policy.getName();
	}

	@Override
	public String getPolicyDescription() {
		return policy.getDescription();
	}

	@Override
	public Long getTimestampDelayTime() {
		TimestampConstraints timestamp = policy.getTimestamp();
		if (timestamp != null) {
			TimeConstraint timestampDelay = timestamp.getTimestampDelay();
			return RuleUtils.convertDuration(timestampDelay.getUnit(), TimeUnit.MILLISECONDS, timestampDelay.getValue());
		}
		return null;
	}

	@Override
	public String getCertifiedRolesAttendance() {
		//	TODO
		//		String attendance = getValue("ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/@Attendance");
		//		return attendance;
		return null;
	}

	@Override
	public CryptographicConstraint getSignatureCryptographicConstraint(final Context context) {
		switch (context) {
			case MAIN_SIGNATURE:
				SignatureConstraints mainSignature = policy.getMainSignature();
				if (mainSignature != null) {
					return mainSignature.getCryptographic();
				}
				break;
			default:
				logger.warn("Unsupported context " + context);
				break;
		}
		return null;
	}

	@Override
	public CryptographicConstraint getSignatureCryptographicConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getCryptographic();
		}
		return null;
	}

	@Override
	public MultiValuesConstraint getSigningCertificateKeyUsageConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getKeyUsage();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateExpirationConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getExpiration();
		}
		return null;
	}

	@Override
	public LevelConstraint getProspectiveCertificateChainConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getProspectiveCertificateChain();
		}
		return null;
	}

	@Override
	public LevelConstraint getCertificateSignatureConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getSignature();
		}
		return null;
	}

	@Override
	public LevelConstraint getRevocationDataAvailableConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getRevocationDataAvailable();
		}
		return null;
	}

	@Override
	public LevelConstraint getRevocationDataIsTrustedConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getRevocationDataIsTrusted();
		}
		return null;
	}

	@Override
	public LevelConstraint getRevocationDataFreshnessConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getRevocationDataFreshness();
		}
		return null;
	}

	//TODO rename
	@Override
	public LevelConstraint getSigningCertificateRevokedConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getRevoked();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateOnHoldConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getOnHold();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateTSLValidityConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getTSLValidity();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateTSLStatusConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getTSLStatus();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateTSLStatusAndValidityConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getTSLStatusAndValidity();
		}
		return null;
	}

	@Override
	public LevelConstraint getIntermediateCertificateRevokedConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getCACertificateByContext(context);
		if (certificateConstraints != null) {
			certificateConstraints.getRevoked();
		}
		return null;
	}

	@Override
	public LevelConstraint getChainConstraint() {
		// TODO not implemented
		//		final String level = getValue("/ConstraintsParameters/MainSignature/CertificateChain/@Level");
		//		if (StringUtils.isNotBlank(level)) {
		//			final Constraint constraint = new Constraint(level);
		//			return constraint;
		//		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateQualificationConstraint() {
		CertificateConstraints certificateConstraints = getCertificateConstraints(Context.MAIN_SIGNATURE, SubContext.SIGNING_CERT);
		if (certificateConstraints != null) {
			return certificateConstraints.getQualification();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateSupportedBySSCDConstraint() {
		CertificateConstraints certificateConstraints = getCertificateConstraints(Context.MAIN_SIGNATURE, SubContext.SIGNING_CERT);
		if (certificateConstraints != null) {
			return certificateConstraints.getSupportedBySSCD();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateIssuedToLegalPersonConstraint() {
		CertificateConstraints certificateConstraints = getCertificateConstraints(Context.MAIN_SIGNATURE, SubContext.SIGNING_CERT);
		if (certificateConstraints != null) {
			return certificateConstraints.getIssuedToLegalPerson();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateRecognitionConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getRecognition();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateSignedConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getSigned();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateAttributePresentConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getAttributePresent();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateDigestValuePresentConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getDigestValuePresent();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateDigestValueMatchConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getDigestValueMatch();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateIssuerSerialMatchConstraint(final Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getIssuerSerialMatch();
		}
		return null;
	}

	@Override
	public LevelConstraint getReferenceDataExistenceConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			return mainSignature.getReferenceDataExistence();
		}
		return null;
	}

	@Override
	public LevelConstraint getReferenceDataIntactConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			return mainSignature.getReferenceDataIntact();
		}
		return null;
	}

	@Override
	public LevelConstraint getSignatureIntactConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			return mainSignature.getSignatureIntact();
		}
		return null;
	}

	@Override
	public BasicValidationProcessValidConstraint getBasicValidationProcessConclusionConstraint() {
		final BasicValidationProcessValidConstraint constraint = new BasicValidationProcessValidConstraint(eu.europa.esig.dss.validation.policy.Constraint.Level.FAIL);
		constraint.setExpectedValue("TRUE"); //TODO
		return constraint;
	}

	@Override
	public LevelConstraint getMessageImprintDataFoundConstraint() {
		TimestampConstraints timestamp = policy.getTimestamp();
		if (timestamp != null) {
			return timestamp.getMessageImprintDataFound();
		}
		return null;
	}

	@Override
	public LevelConstraint getMessageImprintDataIntactConstraint() {
		TimestampConstraints timestamp = policy.getTimestamp();
		if (timestamp != null) {
			return timestamp.getMessageImprintDataIntact();
		}
		return null;
	}

	@Override
	public TimestampValidationProcessValidConstraint getTimestampValidationProcessConstraint() {
		final TimestampValidationProcessValidConstraint constraint = new TimestampValidationProcessValidConstraint(eu.europa.esig.dss.validation.policy.Constraint.Level.FAIL);
		constraint.setExpectedValue("TRUE"); // TODO
		return constraint;
	}

	@Override
	public LevelConstraint getRevocationTimeConstraint() {
		TimestampConstraints timestamp = policy.getTimestamp();
		if (timestamp != null) {
			return timestamp.getRevocationTimeAgainstBestSignatureTime();
		}
		return null;
	}

	@Override
	public LevelConstraint getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint() {
		TimestampConstraints timestamp = policy.getTimestamp();
		if (timestamp != null) {
			return timestamp.getBestSignatureTimeBeforeIssuanceDateOfSigningCertificate();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateValidityAtBestSignatureTimeConstraint() {
		TimestampConstraints timestamp = policy.getTimestamp();
		if (timestamp != null) {
			return timestamp.getSigningCertificateValidityAtBestSignatureTime();
		}
		return null;
	}

	@Override
	public LevelConstraint getAlgorithmReliableAtBestSignatureTimeConstraint() {
		TimestampConstraints timestamp = policy.getTimestamp();
		if (timestamp != null) {
			return timestamp.getAlgorithmReliableAtBestSignatureTime();
		}
		return null;
	}

	@Override
	public LevelConstraint getTimestampCoherenceConstraint() {
		TimestampConstraints timestampConstraints = policy.getTimestamp();
		if (timestampConstraints != null) {
			return timestampConstraints.getCoherence();
		}
		return null;
	}

	@Override
	public LevelConstraint getTimestampDelaySigningTimePropertyConstraint() {
		final Long timestampDelay = getTimestampDelayTime();
		if ((timestampDelay != null) && (timestampDelay > 0)) {
			LevelConstraint constraint = new LevelConstraint();
			constraint.setLevel(Level.FAIL);
			return constraint;
		}
		return null;
	}

	@Override
	public LevelConstraint getContentTimestampImprintIntactConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			SignedAttributesConstraints mandatedSignedQProperties = mainSignature.getMandatedSignedQProperties();
			if (mandatedSignedQProperties != null) {
				TimestampConstraints contentTimeStamp = mandatedSignedQProperties.getContentTimeStamp();
				if (contentTimeStamp != null) {
					return contentTimeStamp.getMessageImprintDataIntact();
				}
			}
		}
		return null;
	}

	@Override
	public LevelConstraint getContentTimestampImprintFoundConstraint() {
		SignatureConstraints mainSignature = policy.getMainSignature();
		if (mainSignature != null) {
			SignedAttributesConstraints mandatedSignedQProperties = mainSignature.getMandatedSignedQProperties();
			if (mandatedSignedQProperties != null) {
				TimestampConstraints contentTimeStamp = mandatedSignedQProperties.getContentTimeStamp();
				if (contentTimeStamp != null) {
					return contentTimeStamp.getMessageImprintDataFound();
				}
			}
		}
		return null;
	}

	private CertificateConstraints getSigningCertificateByContext(Context context) {
		return getCertificateConstraints(context, SubContext.SIGNING_CERT);
	}

	private CertificateConstraints getCACertificateByContext(Context context) {
		return getCertificateConstraints(context, SubContext.CA_CERTIFICATE);
	}

	private CertificateConstraints getCertificateConstraints(Context context, SubContext subContext) {
		switch (context) {
			case MAIN_SIGNATURE:
				SignatureConstraints mainSignature = policy.getMainSignature();
				if (mainSignature != null) {
					if (SubContext.SIGNING_CERT.equals(subContext)) {
						return mainSignature.getSigningCertificate();
					} else if (SubContext.CA_CERTIFICATE.equals(subContext)) {
						return mainSignature.getCACertificate();
					}
				}
				break;
			case TIMESTAMP:
				TimestampConstraints timestampConstraints = policy.getTimestamp();
				if (timestampConstraints != null) {
					if (SubContext.SIGNING_CERT.equals(subContext)) {
						return timestampConstraints.getSigningCertificate();
					} else if (SubContext.CA_CERTIFICATE.equals(subContext)) {
						return timestampConstraints.getCACertificate();
					}
				}
				break;
			case REVOCATION:
				RevocationConstraints revocationConstraints = policy.getRevocation();
				if (revocationConstraints != null) {
					if (SubContext.SIGNING_CERT.equals(subContext)) {
						return revocationConstraints.getSigningCertificate();
					} else if (SubContext.CA_CERTIFICATE.equals(subContext)) {
						return revocationConstraints.getCACertificate();
					}
				}
				break;
			default:
				logger.warn("Unsupported context " + context + " subcontext " + subContext);
				break;
		}
		return null;
	}

}
