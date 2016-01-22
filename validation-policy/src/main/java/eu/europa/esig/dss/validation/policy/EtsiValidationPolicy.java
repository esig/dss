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

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.validation.DateUtils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.AlgoExpirationDate;
import eu.europa.esig.jaxb.policy.BasicSignatureConstraints;
import eu.europa.esig.jaxb.policy.CertificateConstraints;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;
import eu.europa.esig.jaxb.policy.RevocationConstraints;
import eu.europa.esig.jaxb.policy.SignatureConstraints;
import eu.europa.esig.jaxb.policy.SignedAttributesConstraints;
import eu.europa.esig.jaxb.policy.TimeConstraint;
import eu.europa.esig.jaxb.policy.TimestampConstraints;
import eu.europa.esig.jaxb.policy.UnsignedAttributesConstraints;
import eu.europa.esig.jaxb.policy.ValueConstraint;

/**
 * This class encapsulates the constraint file that controls the policy to be
 * used during the validation process. It adds the functions to direct access to
 * the file data. It is the implementation of the ETSI 102853 standard.
 */
public class EtsiValidationPolicy implements ValidationPolicy {

	private static final Logger logger = LoggerFactory.getLogger(EtsiValidationPolicy.class);

	private ConstraintsParameters policy;

	public EtsiValidationPolicy(ConstraintsParameters policy) {
		this.policy = policy;
	}

	@Override
	public Date getAlgorithmExpirationDate(final String algorithm, Context context, SubContext subContext) {
		CryptographicConstraint signatureCryptographicConstraint = getCertificateCryptographicConstraint(context, subContext);
		if (signatureCryptographicConstraint != null) {
			return extractExpirationDate(algorithm, signatureCryptographicConstraint);
		}
		signatureCryptographicConstraint = getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT);
		if (signatureCryptographicConstraint != null) {
			return extractExpirationDate(algorithm, signatureCryptographicConstraint);
		}
		return null;
	}

	private Date extractExpirationDate(final String algorithm, CryptographicConstraint signatureCryptographicConstraint) {
		AlgoExpirationDate algoExpirationDate = signatureCryptographicConstraint.getAlgoExpirationDate();
		String dateFormat = DateUtils.DEFAULT_DATE_FORMAT;
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
	public MultiValuesConstraint getSignaturePolicyConstraint(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return signatureConstraints.getAcceptablePolicies();
		}
		return null;
	}

	@Override
	public LevelConstraint getStructuralValidationConstraint(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return signatureConstraints.getStructuralValidation();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningTimeConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributeConstraints = mainSignature.getSignedAttributes();
			if (signedAttributeConstraints != null) {
				return signedAttributeConstraints.getSigningTime();
			}
		}
		return null;
	}

	@Override
	public ValueConstraint getContentTypeConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributeConstraints = mainSignature.getSignedAttributes();
			if (signedAttributeConstraints != null) {
				return signedAttributeConstraints.getContentType();
			}
		}
		return null;
	}

	@Override
	public LevelConstraint getCounterSignatureConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			UnsignedAttributesConstraints unsignedAttributeConstraints = mainSignature.getUnsignedAttributes();
			if (unsignedAttributeConstraints != null) {
				return unsignedAttributeConstraints.getCounterSignature();
			}
		}
		return null;
	}

	@Override
	public ValueConstraint getContentHintsConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributeConstraints = mainSignature.getSignedAttributes();
			if (signedAttributeConstraints != null) {
				return signedAttributeConstraints.getContentHints();
			}
		}
		return null;
	}

	@Override
	public ValueConstraint getContentIdentifierConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributeConstraints = mainSignature.getSignedAttributes();
			if (signedAttributeConstraints != null) {
				return signedAttributeConstraints.getContentIdentifier();
			}
		}
		return null;
	}

	@Override
	public MultiValuesConstraint getCommitmentTypeIndicationConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributeConstraints = mainSignature.getSignedAttributes();
			if (signedAttributeConstraints != null) {
				return signedAttributeConstraints.getCommitmentTypeIndication();
			}
		}
		return null;
	}

	@Override
	public LevelConstraint getSignerLocationConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributeConstraints = mainSignature.getSignedAttributes();
			if (signedAttributeConstraints != null) {
				return signedAttributeConstraints.getSignerLocation();
			}
		}
		return null;
	}

	@Override
	public MultiValuesConstraint getClaimedRoleConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributes = mainSignature.getSignedAttributes();
			if (signedAttributes != null) {
				return signedAttributes.getClaimedRoles();
			}
		}
		return null;
	}

	@Override
	public MultiValuesConstraint getCertifiedRolesConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributes = mainSignature.getSignedAttributes();
			if (signedAttributes != null) {
				return signedAttributes.getCertifiedRoles();
			}
		}
		return null;
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
	public CryptographicConstraint getSignatureCryptographicConstraint(Context context) {
		BasicSignatureConstraints basicSignature = getBasicSignatureConstraintsByContext(context);
		if (basicSignature != null) {
			return basicSignature.getCryptographic();
		}
		return null;
	}

	@Override
	public CryptographicConstraint getCertificateCryptographicConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return certificateConstraints.getCryptographic();
		}
		return null;
	}

	@Override
	public MultiValuesConstraint getSigningCertificateKeyUsageConstraint(final Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
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
	public LevelConstraint getCertificateRevokedConstraint(final Context context, final SubContext subContext) {
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
	public LevelConstraint getSigningCertificateTSLValidityConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getTSLValidity();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateTSLStatusConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getTSLStatus();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateTSLStatusAndValidityConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getTSLStatusAndValidity();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateQualificationConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getQualification();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateSupportedBySSCDConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getSupportedBySSCD();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateIssuedToLegalPersonConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getIssuedToLegalPerson();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateRecognitionConstraint(Context context) {
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
	public LevelConstraint getSigningCertificateAttributePresentConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getAttributePresent();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateDigestValuePresentConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getDigestValuePresent();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateDigestValueMatchConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getDigestValueMatch();
		}
		return null;
	}

	@Override
	public LevelConstraint getSigningCertificateIssuerSerialMatchConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return certificateConstraints.getIssuerSerialMatch();
		}
		return null;
	}

	@Override
	public LevelConstraint getReferenceDataExistenceConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return basicSignatureConstraints.getReferenceDataExistence();
		}
		return null;
	}

	@Override
	public LevelConstraint getReferenceDataIntactConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return basicSignatureConstraints.getReferenceDataIntact();
		}
		return null;
	}

	@Override
	public LevelConstraint getSignatureIntactConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return basicSignatureConstraints.getSignatureIntact();
		}
		return null;
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
	public TimeConstraint getTimestampDelaySigningTimePropertyConstraint() {
		TimestampConstraints timestampConstraints = policy.getTimestamp();
		if (timestampConstraints != null) {
			return timestampConstraints.getTimestampDelay();
		}
		return null;
	}

	@Override
	public TimeConstraint getRevocationFreshnessConstraint() {
		RevocationConstraints revocationConstraints = policy.getRevocation();
		if (revocationConstraints != null) {
			return revocationConstraints.getRevocationFreshness();
		}
		return null;
	}

	@Override
	public LevelConstraint getContentTimestampConstraint() {
		SignatureConstraints mainSignature = policy.getSignatureConstraints();
		if (mainSignature != null) {
			SignedAttributesConstraints signedAttributeConstraints = mainSignature.getSignedAttributes();
			if (signedAttributeConstraints != null) {
				return signedAttributeConstraints.getContentTimeStamp();
			}
		}
		return null;
	}

	private CertificateConstraints getSigningCertificateByContext(Context context) {
		return getCertificateConstraints(context, SubContext.SIGNING_CERT);
	}

	private CertificateConstraints getCertificateConstraints(Context context, SubContext subContext) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			if (SubContext.SIGNING_CERT.equals(subContext)) {
				return basicSignatureConstraints.getSigningCertificate();
			} else if (SubContext.CA_CERTIFICATE.equals(subContext)) {
				return basicSignatureConstraints.getCACertificate();
			}
		}
		return null;
	}

	private BasicSignatureConstraints getBasicSignatureConstraintsByContext(Context context) {
		switch (context) {
		case SIGNATURE:
			SignatureConstraints mainSignature = policy.getSignatureConstraints();
			if (mainSignature != null) {
				return mainSignature.getBasicSignatureConstraints();
			}
			break;
		case COUNTER_SIGNATURE:
			SignatureConstraints counterSignature = policy.getCounterSignatureConstraints();
			if (counterSignature != null) {
				return counterSignature.getBasicSignatureConstraints();
			}
			break;
		case TIMESTAMP:
			TimestampConstraints timestampConstraints = policy.getTimestamp();
			if (timestampConstraints != null) {
				return timestampConstraints.getBasicSignatureConstraints();
			}
			break;
		case REVOCATION:
			RevocationConstraints revocationConstraints = policy.getRevocation();
			if (revocationConstraints != null) {
				return revocationConstraints.getBasicSignatureConstraints();
			}
		default:
			logger.warn("Unsupported context " + context);
			break;
		}
		return null;
	}

	private SignatureConstraints getSignatureConstraintsByContext(Context context) {
		switch (context) {
		case SIGNATURE:
			return policy.getSignatureConstraints();
		case COUNTER_SIGNATURE:
			return policy.getCounterSignatureConstraints();
		default:
			logger.warn("Unsupported context " + context);
			break;
		}
		return null;
	}

}
