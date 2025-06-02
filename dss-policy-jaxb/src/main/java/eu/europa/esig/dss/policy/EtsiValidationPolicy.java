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
package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.ValidationModel;
import eu.europa.esig.dss.model.policy.CertificateApplicabilityRule;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.DurationRule;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.model.policy.NumericValueRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValueRule;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.ContainerConstraints;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.EIDAS;
import eu.europa.esig.dss.policy.jaxb.EvidenceRecordConstraints;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.ModelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.PDFAConstraints;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.policy.jaxb.UnsignedAttributesConstraints;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. It
 * adds the functions to direct access to the file data.
 * It is the implementation of the ETSI TS 102 853 standard.
 *
 */
public class EtsiValidationPolicy implements ValidationPolicy {

	private static final Logger LOG = LoggerFactory.getLogger(EtsiValidationPolicy.class);

	/** The default validation model (SHELL) */
	private static final ValidationModel DEFAULT_VALIDATION_MODEL = ValidationModel.SHELL;

	/** Validation policy constraints */
	private ConstraintsParameters policy;

	/**
	 * Default constructor
	 *
	 * @param policy {@link ConstraintsParameters}
	 */
	public EtsiValidationPolicy(ConstraintsParameters policy) {
		this.policy = policy;
	}

	@Override
	public MultiValuesRule getSignaturePolicyConstraint(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return toRule(signatureConstraints.getAcceptablePolicies());
		}
		return null;
	}

	@Override
	public LevelRule getSignaturePolicyIdentifiedConstraint(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return toLevelRule(signatureConstraints.getPolicyAvailable());
		}
		return null;
	}
	
	@Override
	public LevelRule getSignaturePolicyStorePresentConstraint(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return toLevelRule(signatureConstraints.getSignaturePolicyStorePresent());
		}
		return null;
	}

	@Override
	public LevelRule getSignaturePolicyPolicyHashValid(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return toLevelRule(signatureConstraints.getPolicyHashMatch());
		}
		return null;
	}

	@Override
	public MultiValuesRule getSignatureFormatConstraint(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return toRule(signatureConstraints.getAcceptableFormats());
		}
		return null;
	}
	
	@Override
	public LevelRule getSignerInformationStoreConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getSignerInformationStore());
		}
		return null;
	}
	
	@Override
	public LevelRule getByteRangeConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getByteRange());
		}
		return null;
	}

	@Override
	public LevelRule getByteRangeCollisionConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getByteRangeCollision());
		}
		return null;
	}

	@Override
	public LevelRule getByteRangeAllDocumentConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getByteRangeAllDocument());
		}
		return null;
	}

	@Override
	public LevelRule getPdfSignatureDictionaryConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getPdfSignatureDictionary());
		}
		return null;
	}

	@Override
	public LevelRule getPdfPageDifferenceConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getPdfPageDifference());
		}
		return null;
	}

	@Override
	public LevelRule getPdfAnnotationOverlapConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getPdfAnnotationOverlap());
		}
		return null;
	}
	
	@Override
	public LevelRule getPdfVisualDifferenceConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getPdfVisualDifference());
		}
		return null;
	}

	@Override
	public LevelRule getDocMDPConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getDocMDP());
		}
		return null;
	}

	@Override
	public LevelRule getFieldMDPConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getFieldMDP());
		}
		return null;
	}

	@Override
	public LevelRule getSigFieldLockConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getSigFieldLock());
		}
		return null;
	}

	@Override
	public LevelRule getFormFillChangesConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getFormFillChanges());
		}
		return null;
	}

	@Override
	public LevelRule getAnnotationChangesConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getAnnotationChanges());
		}
		return null;
	}

	@Override
	public LevelRule getUndefinedChangesConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getUndefinedChanges());
		}
		return null;
	}

	@Override
	public LevelRule getStructuralValidationConstraint(Context context) {
		SignatureConstraints signatureConstraints = getSignatureConstraintsByContext(context);
		if (signatureConstraints != null) {
			return toLevelRule(signatureConstraints.getStructuralValidation());
		}
		return null;
	}
	
	@Override
	public LevelRule getSigningCertificateRefersCertificateChainConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getSigningCertificateRefersCertificateChain());
		}
		return null;
	}
	
	@Override
	public LevelRule getReferencesToAllCertificateChainPresentConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getReferencesToAllCertificateChainPresent());
		}
		return null;
	}

	@Override
	public LevelRule getSigningCertificateDigestAlgorithmConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getSigningCertificateDigestAlgorithm());
		}
		return null;
	}

	@Override
	public LevelRule getSigningDurationRule(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getSigningTime());
		}
		return null;
	}

	@Override
	public ValueRule getContentTypeConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toRule(signedAttributeConstraints.getContentType());
		}
		return null;
	}

	@Override
	public LevelRule getCounterSignatureConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getCounterSignature());
		}
		return null;
	}

	@Override
	public LevelRule getSignatureTimeStampConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getSignatureTimeStamp());
		}
		return null;
	}

	@Override
	public LevelRule getValidationDataTimeStampConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getValidationDataTimeStamp());
		}
		return null;
	}

	@Override
	public LevelRule getValidationDataRefsOnlyTimeStampConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getValidationDataRefsOnlyTimeStamp());
		}
		return null;
	}

	@Override
	public LevelRule getArchiveTimeStampConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getArchiveTimeStamp());
		}
		return null;
	}

	@Override
	public LevelRule getDocumentTimeStampConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getDocumentTimeStamp());
		}
		return null;
	}

	@Override
	public LevelRule getTLevelTimeStampConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getTLevelTimeStamp());
		}
		return null;
	}

	@Override
	public LevelRule getLTALevelTimeStampConstraint(Context context) {
		UnsignedAttributesConstraints unsignedAttributeConstraints = getUnsignedAttributeConstraints(context);
		if (unsignedAttributeConstraints != null) {
			return toLevelRule(unsignedAttributeConstraints.getLTALevelTimeStamp());
		}
		return null;
	}

	@Override
	public ValueRule getContentHintsConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toRule(signedAttributeConstraints.getContentHints());
		}
		return null;
	}

	@Override
	public ValueRule getContentIdentifierConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toRule(signedAttributeConstraints.getContentIdentifier());
		}
		return null;
	}

	@Override
	public LevelRule getMessageDigestOrSignedPropertiesConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getMessageDigestOrSignedPropertiesPresent());
		}
		return null;
	}

	@Override
	public LevelRule getEllipticCurveKeySizeConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getEllipticCurveKeySize());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCommitmentTypeIndicationConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toRule(signedAttributeConstraints.getCommitmentTypeIndication());
		}
		return null;
	}

	@Override
	public LevelRule getSignerLocationConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getSignerLocation());
		}
		return null;
	}

	@Override
	public MultiValuesRule getClaimedRoleConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toRule(signedAttributeConstraints.getClaimedRoles());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertifiedRolesConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toRule(signedAttributeConstraints.getCertifiedRoles());
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
	public CryptographicSuite getSignatureCryptographicConstraint(Context context) {
		CryptographicConstraint sigCryptographic = new CryptographicConstraint();
		BasicSignatureConstraints basicSignature = getBasicSignatureConstraintsByContext(context);
		if (basicSignature != null && basicSignature.getCryptographic() != null) {
			sigCryptographic = basicSignature.getCryptographic();
		}
		initializeCryptographicSuite(sigCryptographic, getCryptographic());
		return toCryptographicSuite(sigCryptographic);
	}

	private CryptographicConstraint getSignatureCryptographic(Context context) {
		CryptographicConstraint sigCryptographic = new CryptographicConstraint();
		BasicSignatureConstraints basicSignature = getBasicSignatureConstraintsByContext(context);
		if (basicSignature != null && basicSignature.getCryptographic() != null) {
			sigCryptographic = basicSignature.getCryptographic();
		}
		initializeCryptographicSuite(sigCryptographic, getCryptographic());
		return sigCryptographic;
	}

	@Override
	public CryptographicSuite getCertificateCryptographicConstraint(Context context, SubContext subContext) {
		CryptographicConstraint certCryptographic = new CryptographicConstraint();
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null && certificateConstraints.getCryptographic() != null) {
			certCryptographic = certificateConstraints.getCryptographic();
		}
		initializeCryptographicSuite(certCryptographic, getSignatureCryptographic(context));
		return toCryptographicSuite(certCryptographic);
	}
	
	/**
	 * Overrides all empty fields for the given {@code CryptographicConstraint}
	 * by the default {@link CryptographicConstraint}
	 *
	 * @param cryptographicConstraint {@link CryptographicConstraint}
	 * @param defaultConstraint {@link CryptographicConstraint}
	 */
	private void initializeCryptographicSuite(CryptographicConstraint cryptographicConstraint, CryptographicConstraint defaultConstraint) {
		if (defaultConstraint != null) {
			if (cryptographicConstraint.getAcceptableDigestAlgo() == null) {
				cryptographicConstraint.setAcceptableDigestAlgo(defaultConstraint.getAcceptableDigestAlgo());
			}
			if (cryptographicConstraint.getAcceptableEncryptionAlgo() == null) {
				cryptographicConstraint.setAcceptableEncryptionAlgo(defaultConstraint.getAcceptableEncryptionAlgo());
			}
			if (cryptographicConstraint.getAlgoExpirationDate() == null) {
				cryptographicConstraint.setAlgoExpirationDate(defaultConstraint.getAlgoExpirationDate());
			}
			if (cryptographicConstraint.getLevel() == null) {
				cryptographicConstraint.setLevel(defaultConstraint.getLevel());
			}
			if (cryptographicConstraint.getMiniPublicKeySize() == null) {
				cryptographicConstraint.setMiniPublicKeySize(defaultConstraint.getMiniPublicKeySize());
			}
		}
	}

	@Override
	public LevelRule getCertificateCAConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getCA());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateIssuerNameConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getIssuerName());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateMaxPathLengthConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getMaxPathLength());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateKeyUsageConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getKeyUsage());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateExtendedKeyUsageConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getExtendedKeyUsage());
		}
		return null;
	}

	@Override
	public LevelRule getCertificatePolicyTreeConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getPolicyTree());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateNameConstraintsConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getNameConstraints());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateNoRevAvailConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getNoRevAvail());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateSupportedCriticalExtensionsConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getSupportedCriticalExtensions());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateForbiddenExtensionsConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getForbiddenExtensions());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateSurnameConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getSurname());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateGivenNameConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getGivenName());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateCommonNameConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getCommonName());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificatePseudonymConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getPseudonym());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateTitleConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getTitle());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateEmailConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getEmail());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateCountryConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getCountry());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateLocalityConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getLocality());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateStateConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getState());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateOrganizationIdentifierConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getOrganizationIdentifier());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateOrganizationNameConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getOrganizationName());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateOrganizationUnitConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getOrganizationUnit());
		}
		return null;
	}

	@Override
	public LevelRule getCertificatePseudoUsageConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getUsePseudonym());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateSerialNumberConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getSerialNumberPresent());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateNotExpiredConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getNotExpired());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateSunsetDateConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getSunsetDate());
		}
		return null;
	}

	@Override
	public LevelRule getProspectiveCertificateChainConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getProspectiveCertificateChain());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateAuthorityInfoAccessPresentConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getAuthorityInfoAccessPresent());
		}
		return null;
	}

	@Override
	public CertificateApplicabilityRule getRevocationDataSkipConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null && certificateConstraints.getRevocationDataSkip() != null) {
			return toRule(certificateConstraints.getRevocationDataSkip());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateRevocationInfoAccessPresentConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getRevocationInfoAccessPresent());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateSignatureConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getSignature());
		}
		return null;
	}

	@Override
	public LevelRule getUnknownStatusConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			return toLevelRule(revocationConstraints.getUnknownStatus());
		}
		return null;
	}
	
	@Override
	public LevelRule getThisUpdatePresentConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			LevelConstraint constraint = revocationConstraints.getThisUpdatePresent();
			if (constraint == null) {
				// TODO : temporary handling since 6.3 to ensure smooth migration to DSS 6.4. To be removed in 6.4.
				constraint = new LevelConstraint();
				constraint.setLevel(Level.FAIL);
				LOG.warn("No ThisUpdatePresent constraint is defined in the validation policy for Revocation element! " +
						"Default behavior with FAIL level is added to processing. Please set the constraint explicitly. To be required since DSS 6.4.");
			}
			return toLevelRule(constraint);
		}
		return null;
	}

	@Override
	public LevelRule getRevocationIssuerKnownConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			LevelConstraint constraint = revocationConstraints.getRevocationIssuerKnown();
			if (constraint == null) {
				// TODO : temporary handling since 6.3 to ensure smooth migration to DSS 6.4. To be removed in 6.4.
				constraint = new LevelConstraint();
				constraint.setLevel(Level.FAIL);
				LOG.warn("No RevocationIssuerKnown constraint is defined in the validation policy for Revocation element! " +
						"Default behavior with FAIL level is added to processing. Please set the constraint explicitly. To be required since DSS 6.4.");
			}
			return toLevelRule(constraint);
		}
		return null;
	}

	@Override
	public LevelRule getRevocationIssuerValidAtProductionTimeConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			LevelConstraint constraint = revocationConstraints.getRevocationIssuerValidAtProductionTime();
			if (constraint == null) {
				// TODO : temporary handling since 6.3 to ensure smooth migration to DSS 6.4. To be removed in 6.4.
				constraint = new LevelConstraint();
				constraint.setLevel(Level.FAIL);
				LOG.warn("No RevocationIssuerValidAtProductionTime constraint is defined in the validation policy for Revocation element! " +
						"Default behavior with FAIL level is added to processing. Please set the constraint explicitly. To be required since DSS 6.4.");
			}
			return toLevelRule(constraint);
		}
		return null;
	}

	@Override
	public LevelRule getRevocationAfterCertificateIssuanceConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			LevelConstraint constraint = revocationConstraints.getRevocationAfterCertificateIssuance();
			if (constraint == null) {
				// TODO : temporary handling since 6.3 to ensure smooth migration to DSS 6.4. To be removed in 6.4.
				constraint = new LevelConstraint();
				constraint.setLevel(Level.FAIL);
				LOG.warn("No RevocationIssuerKnowsCertificate constraint is defined in the validation policy for Revocation element! " +
						"Default behavior with FAIL level is added to processing. Please set the constraint explicitly. To be required since DSS 6.4.");
			}
			return toLevelRule(constraint);
		}
		return null;
	}

	@Override
	public LevelRule getRevocationHasInformationAboutCertificateConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			LevelConstraint constraint = revocationConstraints.getRevocationHasInformationAboutCertificate();
			if (constraint == null) {
				// TODO : temporary handling since 6.3 to ensure smooth migration to DSS 6.4. To be removed in 6.4.
				constraint = new LevelConstraint();
				constraint.setLevel(Level.FAIL);
				LOG.warn("No RevocationIssuerHasInformationAboutCertificate constraint is defined in the validation policy for Revocation element! " +
						"Default behavior with FAIL level is added to processing. Please set the constraint explicitly. To be required since DSS 6.4.");
			}
			return toLevelRule(constraint);
		}
		return null;
	}

	@Override
	public LevelRule getOCSPResponseResponderIdMatchConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			return toLevelRule(revocationConstraints.getOCSPResponderIdMatch());
		}
		return null;
	}

	@Override
	public LevelRule getOCSPResponseCertHashPresentConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			return toLevelRule(revocationConstraints.getOCSPCertHashPresent());
		}
		return null;
	}

	@Override
	public LevelRule getOCSPResponseCertHashMatchConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			return toLevelRule(revocationConstraints.getOCSPCertHashMatch());
		}
		return null;
	}

	@Override
	public LevelRule getSelfIssuedOCSPConstraint() {
		RevocationConstraints revocationConstraints = getRevocationConstraints();
		if (revocationConstraints != null) {
			return toLevelRule(revocationConstraints.getSelfIssuedOCSP());
		}
		return null;
	}

	@Override
	public LevelRule getRevocationDataAvailableConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getRevocationDataAvailable());
		}
		return null;
	}

	@Override
	public LevelRule getAcceptableRevocationDataFoundConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getAcceptableRevocationDataFound());
		}
		return null;
	}

	@Override
	public LevelRule getCRLNextUpdatePresentConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getCRLNextUpdatePresent());
		}
		return null;
	}

	@Override
	public LevelRule getOCSPNextUpdatePresentConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getOCSPNextUpdatePresent());
		}
		return null;
	}

	@Override
	public DurationRule getRevocationFreshnessConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getRevocationFreshness());
		}
		return null;
	}

	@Override
	public LevelRule getRevocationFreshnessNextUpdateConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getRevocationFreshnessNextUpdate());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateNotRevokedConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getNotRevoked());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateNotOnHoldConstraint(final Context context, final SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getNotOnHold());
		}
		return null;
	}

	@Override
	public LevelRule getRevocationIssuerNotExpiredConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getRevocationIssuerNotExpired());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateNotSelfSignedConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getNotSelfSigned());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateSelfSignedConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getSelfSigned());
		}
		return null;
	}

	@Override
	public MultiValuesRule getTrustServiceStatusConstraint(Context context) {
		BasicSignatureConstraints sigConstraints = getBasicSignatureConstraintsByContext(context);
		if (sigConstraints != null) {
			return toRule(sigConstraints.getTrustServiceStatus());
		}
		return null;
	}

	@Override
	public MultiValuesRule getTrustServiceTypeIdentifierConstraint(Context context) {
		BasicSignatureConstraints sigConstraints = getBasicSignatureConstraintsByContext(context);
		if (sigConstraints != null) {
			return toRule(sigConstraints.getTrustServiceTypeIdentifier());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificatePolicyIdsConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getPolicyIds());
		}
		return null;
	}

	@Override
	public LevelRule getCertificatePolicyQualificationIdsConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getPolicyQualificationIds());
		}
		return null;
	}

	@Override
	public LevelRule getCertificatePolicySupportedByQSCDIdsConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getPolicySupportedByQSCDIds());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateQCComplianceConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getQcCompliance());
		}
		return null;
	}

	@Override
	public ValueRule getCertificateQcEuLimitValueCurrencyConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getQcEuLimitValueCurrency());
		}
		return null;
	}

	@Override
	public NumericValueRule getCertificateMinQcEuLimitValueConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getMinQcEuLimitValue());
		}
		return null;
	}

	@Override
	public NumericValueRule getCertificateMinQcEuRetentionPeriodConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getMinQcEuRetentionPeriod());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateQcSSCDConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getQcSSCD());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateQcEuPDSLocationConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getQcEuPDSLocation());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateQcTypeConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getQcType());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateQcCCLegislationConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getQcLegislationCountryCodes());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateIssuedToNaturalPersonConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getIssuedToNaturalPerson());
		}
		return null;
	}

	@Override
	public LevelRule getCertificateIssuedToLegalPersonConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getIssuedToLegalPerson());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificateSemanticsIdentifierConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getSemanticsIdentifier());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificatePS2DQcTypeRolesOfPSPConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getPSD2QcTypeRolesOfPSP());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificatePS2DQcCompetentAuthorityNameConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getPSD2QcCompetentAuthorityName());
		}
		return null;
	}

	@Override
	public MultiValuesRule getCertificatePS2DQcCompetentAuthorityIdConstraint(Context context, SubContext subContext) {
		CertificateConstraints certificateConstraints = getCertificateConstraints(context, subContext);
		if (certificateConstraints != null) {
			return toRule(certificateConstraints.getPSD2QcCompetentAuthorityId());
		}
		return null;
	}

	@Override
	public LevelRule getSigningCertificateRecognitionConstraint(Context context) {
		CertificateConstraints certificateConstraints = getSigningCertificateByContext(context);
		if (certificateConstraints != null) {
			return toLevelRule(certificateConstraints.getRecognition());
		}
		return null;
	}

	@Override
	public LevelRule getSigningCertificateAttributePresentConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getSigningCertificatePresent());
		}
		return null;
	}

	@Override
	public LevelRule getUnicitySigningCertificateAttributeConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getUnicitySigningCertificate());
		}
		return null;
	}

	@Override
	public LevelRule getSigningCertificateDigestValuePresentConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getCertDigestPresent());
		}
		return null;
	}

	@Override
	public LevelRule getSigningCertificateDigestValueMatchConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getCertDigestMatch());
		}
		return null;
	}

	@Override
	public LevelRule getSigningCertificateIssuerSerialMatchConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getIssuerSerialMatch());
		}
		return null;
	}

	@Override
	public LevelRule getKeyIdentifierPresent(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getKeyIdentifierPresent());
		}
		return null;
	}

	@Override
	public LevelRule getKeyIdentifierMatch(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getKeyIdentifierMatch());
		}
		return null;
	}

	@Override
	public LevelRule getReferenceDataExistenceConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getReferenceDataExistence());
		}
		return null;
	}

	@Override
	public LevelRule getReferenceDataIntactConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getReferenceDataIntact());
		}
		return null;
	}

	@Override
	public LevelRule getReferenceDataNameMatchConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getReferenceDataNameMatch());
		}
		return null;
	}

	@Override
	public LevelRule getManifestEntryObjectExistenceConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getManifestEntryObjectExistence());
		}
		return null;
	}

	@Override
	public LevelRule getManifestEntryObjectIntactConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getManifestEntryObjectIntact());
		}
		return null;
	}

	@Override
	public LevelRule getManifestEntryObjectGroupConstraint(Context context) {

		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getManifestEntryObjectGroup());
		}
		return null;
	}

	@Override
	public LevelRule getManifestEntryNameMatchConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getManifestEntryNameMatch());
		}
		return null;
	}

	@Override
	public LevelRule getSignatureIntactConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getSignatureIntact());
		}
		return null;
	}

	@Override
	public LevelRule getSignatureDuplicatedConstraint(Context context) {
		BasicSignatureConstraints basicSignatureConstraints = getBasicSignatureConstraintsByContext(context);
		if (basicSignatureConstraints != null) {
			return toLevelRule(basicSignatureConstraints.getSignatureDuplicated());
		}
		return null;
	}

	@Override
	public LevelRule getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint() {
		TimestampConstraints timestamp = getTimestampConstraints();
		if (timestamp != null) {
			return toLevelRule(timestamp.getBestSignatureTimeBeforeExpirationDateOfSigningCertificate());
		}
		return null;
	}

	@Override
	public LevelRule getRevocationTimeAgainstBestSignatureDurationRule() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getRevocationTimeAgainstBestSignatureTime());
		}
		return null;
	}

	@Override
	public LevelRule getTimestampCoherenceConstraint() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getCoherence());
		}
		return null;
	}

	@Override
	public DurationRule getTimestampDelayConstraint() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toRule(timestampConstraints.getTimestampDelay());
		}
		return null;
	}

	@Override
	public LevelRule getTimestampValidConstraint() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getTimestampValid());
		}
		return null;
	}

	@Override
	public LevelRule getTimestampTSAGeneralNamePresent() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getTSAGeneralNamePresent());
		}
		return null;
	}

	@Override
	public LevelRule getTimestampTSAGeneralNameContentMatch() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getTSAGeneralNameContentMatch());
		}
		return null;
	}

	@Override
	public LevelRule getTimestampTSAGeneralNameOrderMatch() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getTSAGeneralNameOrderMatch());
		}
		return null;
	}

	@Override
	public LevelRule getAtsHashIndexConstraint() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getAtsHashIndex());
		}
		return null;
	}

	@Override
	public LevelRule getTimestampContainerSignedAndTimestampedFilesCoveredConstraint() {
		TimestampConstraints timestampConstraints = getTimestampConstraints();
		if (timestampConstraints != null) {
			return toLevelRule(timestampConstraints.getContainerSignedAndTimestampedFilesCovered());
		}
		return null;
	}

	@Override
	public LevelRule getFullScopeConstraint() {
		SignatureConstraints mainSignature = getSignatureConstraints();
		if (mainSignature != null) {
			return toLevelRule(mainSignature.getFullScope());
		}
		return null;
	}

	@Override
	public LevelRule getContentTimeStampConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getContentTimeStamp());
		}
		return null;
	}

	@Override
	public LevelRule getContentTimeStampMessageImprintConstraint(Context context) {
		SignedAttributesConstraints signedAttributeConstraints = getSignedAttributeConstraints(context);
		if (signedAttributeConstraints != null) {
			return toLevelRule(signedAttributeConstraints.getContentTimeStampMessageImprint());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordValidConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getEvidenceRecordValid());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordDataObjectExistenceConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getDataObjectExistence());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordDataObjectIntactConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getDataObjectIntact());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordDataObjectFoundConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getDataObjectFound());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordDataObjectGroupConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getDataObjectGroup());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordSignedFilesCoveredConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getSignedFilesCovered());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordContainerSignedAndTimestampedFilesCoveredConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getContainerSignedAndTimestampedFilesCovered());
		}
		return null;
	}

	@Override
	public LevelRule getEvidenceRecordHashTreeRenewalConstraint() {
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null) {
			return toLevelRule(evidenceRecordConstraints.getHashTreeRenewal());
		}
		return null;
	}

	@Override
	public CryptographicSuite getEvidenceRecordCryptographicConstraint() {
		CryptographicConstraint evidenceRecordCryptographic = new CryptographicConstraint();
		EvidenceRecordConstraints evidenceRecordConstraints = getEvidenceRecordConstraints();
		if (evidenceRecordConstraints != null && evidenceRecordConstraints.getCryptographic() != null) {
			evidenceRecordCryptographic = evidenceRecordConstraints.getCryptographic();
		}
		initializeCryptographicSuite(evidenceRecordCryptographic, getCryptographic());
		return toCryptographicSuite(evidenceRecordCryptographic);
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
			case CERTIFICATE: // TODO improve
				SignatureConstraints mainSignature = getSignatureConstraints();
				if (mainSignature != null) {
					return mainSignature.getBasicSignatureConstraints();
				}
				break;
			case COUNTER_SIGNATURE:
				SignatureConstraints counterSignature = getCounterSignatureConstraints();
				if (counterSignature != null) {
					return counterSignature.getBasicSignatureConstraints();
				}
				break;
			case TIMESTAMP:
				TimestampConstraints timestampConstraints = getTimestampConstraints();
				if (timestampConstraints != null) {
					return timestampConstraints.getBasicSignatureConstraints();
				}
				break;
			case REVOCATION:
				RevocationConstraints revocationConstraints = getRevocationConstraints();
				if (revocationConstraints != null) {
					return revocationConstraints.getBasicSignatureConstraints();
				}
				break;
			default:
				throw new UnsupportedOperationException(String.format("Unsupported context '%s'", context));
		}
		return null;
	}

	private SignedAttributesConstraints getSignedAttributeConstraints(Context context) {
		switch (context) {
		case SIGNATURE:
		case CERTIFICATE: // TODO improve
			SignatureConstraints mainSignature = getSignatureConstraints();
			if (mainSignature != null) {
				return mainSignature.getSignedAttributes();
			}
			break;
		case COUNTER_SIGNATURE:
			SignatureConstraints counterSignature = getCounterSignatureConstraints();
			if (counterSignature != null) {
				return counterSignature.getSignedAttributes();
			}
			break;
		case TIMESTAMP:
			TimestampConstraints timestampConstraints = getTimestampConstraints();
			if (timestampConstraints != null) {
				return timestampConstraints.getSignedAttributes();
			}
			break;
		default:
			LOG.warn("Unsupported context {}", context);
			break;
		}
		return null;
	}

	private UnsignedAttributesConstraints getUnsignedAttributeConstraints(Context context) {
		switch (context) {
			case SIGNATURE:
				SignatureConstraints mainSignature = getSignatureConstraints();
				if (mainSignature != null) {
					return mainSignature.getUnsignedAttributes();
				}
				break;
			case COUNTER_SIGNATURE:
				SignatureConstraints counterSignature = getCounterSignatureConstraints();
				if (counterSignature != null) {
					return counterSignature.getUnsignedAttributes();
				}
				break;
			default:
				LOG.warn("Unsupported context {}", context);
				break;
		}
		return null;
	}

	private SignatureConstraints getSignatureConstraintsByContext(Context context) {
		switch (context) {
		case SIGNATURE:
		case CERTIFICATE: // TODO improve
			return getSignatureConstraints();
		case COUNTER_SIGNATURE:
			return getCounterSignatureConstraints();
		default:
			LOG.warn("Unsupported context {}", context);
			break;
		}
		return null;
	}

	@Override
	public MultiValuesRule getAcceptedContainerTypesConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toRule(containerConstraints.getAcceptableContainerTypes());
		}
		return null;
	}

	@Override
	public LevelRule getZipCommentPresentConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toLevelRule(containerConstraints.getZipCommentPresent());
		}
		return null;
	}

	@Override
	public MultiValuesRule getAcceptedZipCommentsConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toRule(containerConstraints.getAcceptableZipComment());
		}
		return null;
	}

	@Override
	public LevelRule getMimeTypeFilePresentConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toLevelRule(containerConstraints.getMimeTypeFilePresent());
		}
		return null;
	}

	@Override
	public MultiValuesRule getAcceptedMimeTypeContentsConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toRule(containerConstraints.getAcceptableMimeTypeFileContent());
		}
		return null;
	}

	@Override
	public LevelRule getManifestFilePresentConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toLevelRule(containerConstraints.getManifestFilePresent());
		}
		return null;
	}
	
	@Override
	public LevelRule getSignedFilesPresentConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toLevelRule(containerConstraints.getSignedFilesPresent());
		}
		return null;
	}

	@Override
	public LevelRule getFilenameAdherenceConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toLevelRule(containerConstraints.getFilenameAdherence());
		}
		return null;
	}
	
	@Override
	public LevelRule getAllFilesSignedConstraint() {
		ContainerConstraints containerConstraints = getContainerConstraints();
		if (containerConstraints != null) {
			return toLevelRule(containerConstraints.getAllFilesSigned());
		}
		return null;
	}

	@Override
	public MultiValuesRule getAcceptablePDFAProfilesConstraint() {
		PDFAConstraints pdfaConstraints = getPDFAConstraints();
		if (pdfaConstraints != null) {
			return toRule(pdfaConstraints.getAcceptablePDFAProfiles());
		}
		return null;
	}

	@Override
	public LevelRule getPDFACompliantConstraint() {
		PDFAConstraints pdfaConstraints = getPDFAConstraints();
		if (pdfaConstraints != null) {
			return toLevelRule(pdfaConstraints.getPDFACompliant());
		}
		return null;
	}

	@Override
	public boolean isEIDASConstraintPresent() {
		return getEIDASConstraints() != null;
	}

	@Override
	public DurationRule getTLFreshnessConstraint() {
		EIDAS eIDASConstraints = getEIDASConstraints();
		if (eIDASConstraints != null) {
			return toRule(eIDASConstraints.getTLFreshness());
		}
		return null;
	}

	@Override
	public LevelRule getTLWellSignedConstraint() {
		EIDAS eIDASConstraints = getEIDASConstraints();
		if (eIDASConstraints != null) {
			return toLevelRule(eIDASConstraints.getTLWellSigned());
		}
		return null;
	}

	@Override
	public LevelRule getTLNotExpiredConstraint() {
		EIDAS eIDASConstraints = getEIDASConstraints();
		if (eIDASConstraints != null) {
			return toLevelRule(eIDASConstraints.getTLNotExpired());
		}
		return null;
	}

	@Override
	public MultiValuesRule getTLVersionConstraint() {
		EIDAS eIDASConstraints = getEIDASConstraints();
		if (eIDASConstraints != null) {
			return toRule(eIDASConstraints.getTLVersion());
		}
		return null;
	}

	@Override
	public LevelRule getTLStructureConstraint() {
		EIDAS eIDASConstraints = getEIDASConstraints();
		if (eIDASConstraints != null) {
			return toLevelRule(eIDASConstraints.getTLStructure());
		}
		return null;
	}

	@Override
	public ValidationModel getValidationModel() {
		ValidationModel currentModel = DEFAULT_VALIDATION_MODEL;
		ModelConstraint modelConstraint = policy.getModel();
		if (modelConstraint != null && modelConstraint.getValue() != null) {
			currentModel = modelConstraint.getValue();
		}
		return currentModel;
	}

	/**
	 * Returns the constraint used for Signature validation
	 *
	 * @return {@link SignatureConstraints}
	 */
	public SignatureConstraints getSignatureConstraints() {
		return policy.getSignatureConstraints();
	}

	/**
	 * Returns the constraint used for Counter Signature validation
	 *
	 * @return {@link SignatureConstraints}
	 */
	public SignatureConstraints getCounterSignatureConstraints() {
		return policy.getCounterSignatureConstraints();
	}

	/**
	 * Returns the constraint used for Timestamp validation
	 *
	 * @return {@link TimestampConstraints}
	 */
	public TimestampConstraints getTimestampConstraints() {
		return policy.getTimestamp();
	}

	/**
	 * Returns the constraint used for Revocation validation
	 *
	 * @return {@code RevocationConstraints}
	 */
	public RevocationConstraints getRevocationConstraints() {
		return policy.getRevocation();
	}

	/**
	 * Returns the constraint used for Evidence Record validation
	 *
	 * @return {@code EvidenceRecordConstraints}
	 */
	public EvidenceRecordConstraints getEvidenceRecordConstraints() {
		return policy.getEvidenceRecord();
	}

	/**
	 * Returns the constraint used for ASiC Container validation
	 *
	 * @return {@code ContainerConstraints}
	 */
	public ContainerConstraints getContainerConstraints() {
		return policy.getContainerConstraints();
	}

	/**
	 * Returns the constraint used for ASiC Container validation
	 *
	 * @return {@code ContainerConstraints}
	 */
	public PDFAConstraints getPDFAConstraints() {
		return policy.getPDFAConstraints();
	}

	/**
	 * Returns the constraint used for qualification validation
	 *
	 * @return {@code EIDAS}
	 */
	public EIDAS getEIDASConstraints() {
		return policy.getEIDAS();
	}

	/**
	 * Returns the common constraint used for cryptographic validation
	 *
	 * @return {@code CryptographicConstraint}
	 */
	public CryptographicConstraint getCryptographic() {
		return policy.getCryptographic();
	}

	private LevelConstraintWrapper toLevelRule(LevelConstraint constraint) {
		if (constraint == null) {
			return null;
		}
		return new LevelConstraintWrapper(constraint);
	}

	private MultiValuesConstraintWrapper toRule(MultiValuesConstraint constraint) {
		if (constraint == null) {
			return null;
		}
		return new MultiValuesConstraintWrapper(constraint);
	}

	private ValueConstraintWrapper toRule(ValueConstraint constraint) {
		if (constraint == null) {
			return null;
		}
		return new ValueConstraintWrapper(constraint);
	}

	private IntValueConstraintWrapper toRule(IntValueConstraint constraint) {
		if (constraint == null) {
			return null;
		}
		return new IntValueConstraintWrapper(constraint);
	}

	private TimeConstraintWrapper toRule(TimeConstraint constraint) {
		if (constraint == null) {
			return null;
		}
		return new TimeConstraintWrapper(constraint);
	}

	private CertificateValuesConstraintWrapper toRule(CertificateValuesConstraint constraint) {
		if (constraint == null) {
			return null;
		}
		return new CertificateValuesConstraintWrapper(constraint);
	}

	private CryptographicConstraintWrapper toCryptographicSuite(CryptographicConstraint constraint) {
		return new CryptographicConstraintWrapper(constraint);
	}

	@Override
	public String toString() {
		return "EtsiValidationPolicy [" +
				"policyName=" + getPolicyName() +
				']';
	}

}
