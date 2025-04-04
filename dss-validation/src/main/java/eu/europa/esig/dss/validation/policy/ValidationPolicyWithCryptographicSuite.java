package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.Context;
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
import eu.europa.esig.dss.utils.Utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * This class wraps a provided {@code eu.europa.esig.dss.model.policy.ValidationPolicy} and
 * {@code eu.europa.esig.dss.model.policy.CryptographicSuite}s, whether applicable.
 * The class manages the returned data.
 *
 */
public class ValidationPolicyWithCryptographicSuite implements ValidationPolicy {

    /** The wrapped validation policy */
    private final ValidationPolicy validationPolicy;

    /** Map of cryptographic suite Files and their applicability scopes */
    private final Map<ContextAndSubContext, CryptographicSuite> cryptographicSuitesMap = new HashMap<>();

    /**
     * Default constructor to create a validation policy with cryptographic suites wrapper
     *
     * @param validationPolicy {@link ValidationPolicy}
     */
    public ValidationPolicyWithCryptographicSuite(final ValidationPolicy validationPolicy) {
        Objects.requireNonNull(validationPolicy, "ValidationPolicy cannot be null!");
        this.validationPolicy = validationPolicy;
    }

    /**
     * This method sets global cryptographic suite, to be applied when no context-specific
     * cryptographic rules are defined.
     * The provided cryptographic suite will overwrite the current settings for the global cryptographic suite.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     */
    public void setCryptographicSuite(CryptographicSuite cryptographicSuite) {
        cryptographicSuitesMap.put(new ContextAndSubContext(), cryptographicSuite);
    }

    /**
     * This method sets cryptographic suite for a specific {@code Context} or
     * a combination of a {@code Context} and a {@code SubContext}.
     * The provided cryptographic suite will overwrite the current settings only for the defined applicability scope.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     */
    public void setCryptographicSuite(CryptographicSuite cryptographicSuite, Context context, SubContext subContext) {
        cryptographicSuitesMap.put(new ContextAndSubContext(context, subContext), cryptographicSuite);
    }

    @Override
    public String getPolicyName() {
        return validationPolicy.getPolicyName();
    }

    @Override
    public String getPolicyDescription() {
        return validationPolicy.getPolicyDescription();
    }

    @Override
    public MultiValuesRule getSignaturePolicyConstraint(Context context) {
        return validationPolicy.getSignaturePolicyConstraint(context);
    }

    @Override
    public LevelRule getSignaturePolicyIdentifiedConstraint(Context context) {
        return validationPolicy.getSignaturePolicyIdentifiedConstraint(context);
    }

    @Override
    public LevelRule getSignaturePolicyStorePresentConstraint(Context context) {
        return validationPolicy.getSignaturePolicyStorePresentConstraint(context);
    }

    @Override
    public LevelRule getSignaturePolicyPolicyHashValid(Context context) {
        return validationPolicy.getSignaturePolicyPolicyHashValid(context);
    }

    @Override
    public LevelRule getStructuralValidationConstraint(Context context) {
        return validationPolicy.getStructuralValidationConstraint(context);
    }

    @Override
    public LevelRule getSigningCertificateRefersCertificateChainConstraint(Context context) {
        return validationPolicy.getSigningCertificateRefersCertificateChainConstraint(context);
    }

    @Override
    public LevelRule getReferencesToAllCertificateChainPresentConstraint(Context context) {
        return validationPolicy.getReferencesToAllCertificateChainPresentConstraint(context);
    }

    @Override
    public LevelRule getSigningCertificateDigestAlgorithmConstraint(Context context) {
        return validationPolicy.getSigningCertificateDigestAlgorithmConstraint(context);
    }

    @Override
    public LevelRule getSigningDurationRule(Context context) {
        return validationPolicy.getSigningDurationRule(context);
    }

    @Override
    public ValueRule getContentTypeConstraint(Context context) {
        return validationPolicy.getContentTypeConstraint(context);
    }

    @Override
    public ValueRule getContentHintsConstraint(Context context) {
        return validationPolicy.getContentHintsConstraint(context);
    }

    @Override
    public ValueRule getContentIdentifierConstraint(Context context) {
        return validationPolicy.getContentIdentifierConstraint(context);
    }

    @Override
    public LevelRule getMessageDigestOrSignedPropertiesConstraint(Context context) {
        return validationPolicy.getMessageDigestOrSignedPropertiesConstraint(context);
    }

    @Override
    public LevelRule getEllipticCurveKeySizeConstraint(Context context) {
        return validationPolicy.getEllipticCurveKeySizeConstraint(context);
    }

    @Override
    public MultiValuesRule getCommitmentTypeIndicationConstraint(Context context) {
        return validationPolicy.getCommitmentTypeIndicationConstraint(context);
    }

    @Override
    public LevelRule getSignerLocationConstraint(Context context) {
        return validationPolicy.getSignerLocationConstraint(context);
    }

    @Override
    public LevelRule getContentTimeStampConstraint(Context context) {
        return validationPolicy.getContentTimeStampConstraint(context);
    }

    @Override
    public LevelRule getContentTimeStampMessageImprintConstraint(Context context) {
        return validationPolicy.getContentTimeStampMessageImprintConstraint(context);
    }

    @Override
    public MultiValuesRule getClaimedRoleConstraint(Context context) {
        return validationPolicy.getClaimedRoleConstraint(context);
    }

    @Override
    public MultiValuesRule getCertifiedRolesConstraint(Context context) {
        return validationPolicy.getCertifiedRolesConstraint(context);
    }

    @Override
    public CryptographicSuite getSignatureCryptographicConstraint(Context context) {
        CryptographicSuite cryptographicSuite = getCryptographicSuite(context, null);
        if (cryptographicSuite == null) {
            cryptographicSuite = validationPolicy.getSignatureCryptographicConstraint(context);
        }
        return cryptographicSuite;
    }

    @Override
    public CryptographicSuite getCertificateCryptographicConstraint(Context context, SubContext subContext) {
        CryptographicSuite cryptographicSuite = getCryptographicSuite(context, subContext);
        if (cryptographicSuite == null) {
            cryptographicSuite = validationPolicy.getCertificateCryptographicConstraint(context, subContext);
        }
        return cryptographicSuite;
    }

    @Override
    public CryptographicSuite getEvidenceRecordCryptographicConstraint() {
        CryptographicSuite cryptographicSuite = getCryptographicSuite(Context.EVIDENCE_RECORD, null);
        if (cryptographicSuite == null) {
            cryptographicSuite = validationPolicy.getEvidenceRecordCryptographicConstraint();
        }
        return cryptographicSuite;
    }

    private CryptographicSuite getCryptographicSuite(Context context, SubContext subContext) {
        if (Utils.isMapNotEmpty(cryptographicSuitesMap)) {
            // check for Context + SubContext
            for (ContextAndSubContext contextAndSubContext : cryptographicSuitesMap.keySet()) {
                if (context == contextAndSubContext.getContext() && subContext == contextAndSubContext.getSubContext()) {
                    return cryptographicSuitesMap.get(contextAndSubContext);
                }
            }
            // check for Context
            for (ContextAndSubContext contextAndSubContext : cryptographicSuitesMap.keySet()) {
                if (context == contextAndSubContext.getContext() && contextAndSubContext.getSubContext() == null) {
                    return cryptographicSuitesMap.get(contextAndSubContext);
                }
            }
            // check for global
            for (ContextAndSubContext contextAndSubContext : cryptographicSuitesMap.keySet()) {
                if (contextAndSubContext.getContext() == null && contextAndSubContext.getSubContext() == null) {
                    return cryptographicSuitesMap.get(contextAndSubContext);
                }
            }
        }
        return null;
    }

    @Override
    public LevelRule getCertificateCAConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateCAConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateIssuerNameConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateIssuerNameConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateMaxPathLengthConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateMaxPathLengthConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateKeyUsageConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateKeyUsageConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateExtendedKeyUsageConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateExtendedKeyUsageConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificatePolicyTreeConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePolicyTreeConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateNameConstraintsConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateNameConstraintsConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateNoRevAvailConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateNoRevAvailConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateSupportedCriticalExtensionsConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateSupportedCriticalExtensionsConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateForbiddenExtensionsConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateForbiddenExtensionsConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateNotExpiredConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateNotExpiredConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateSunsetDateConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateSunsetDateConstraint(context, subContext);
    }

    @Override
    public LevelRule getProspectiveCertificateChainConstraint(Context context) {
        return validationPolicy.getProspectiveCertificateChainConstraint(context);
    }

    @Override
    public LevelRule getCertificateSignatureConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateSignatureConstraint(context, subContext);
    }

    @Override
    public LevelRule getUnknownStatusConstraint() {
        return validationPolicy.getUnknownStatusConstraint();
    }

    @Override
    public LevelRule getThisUpdatePresentConstraint() {
        return validationPolicy.getThisUpdatePresentConstraint();
    }

    @Override
    public LevelRule getRevocationIssuerKnownConstraint() {
        return validationPolicy.getRevocationIssuerKnownConstraint();
    }

    @Override
    public LevelRule getRevocationIssuerValidAtProductionTimeConstraint() {
        return validationPolicy.getRevocationIssuerValidAtProductionTimeConstraint();
    }

    @Override
    public LevelRule getRevocationAfterCertificateIssuanceConstraint() {
        return validationPolicy.getRevocationAfterCertificateIssuanceConstraint();
    }

    @Override
    public LevelRule getRevocationHasInformationAboutCertificateConstraint() {
        return validationPolicy.getRevocationHasInformationAboutCertificateConstraint();
    }

    @Override
    public LevelRule getOCSPResponseResponderIdMatchConstraint() {
        return validationPolicy.getOCSPResponseResponderIdMatchConstraint();
    }

    @Override
    public LevelRule getOCSPResponseCertHashPresentConstraint() {
        return validationPolicy.getOCSPResponseCertHashPresentConstraint();
    }

    @Override
    public LevelRule getOCSPResponseCertHashMatchConstraint() {
        return validationPolicy.getOCSPResponseCertHashMatchConstraint();
    }

    @Override
    public LevelRule getSelfIssuedOCSPConstraint() {
        return validationPolicy.getSelfIssuedOCSPConstraint();
    }

    @Override
    public LevelRule getRevocationDataAvailableConstraint(Context context, SubContext subContext) {
        return validationPolicy.getRevocationDataAvailableConstraint(context, subContext);
    }

    @Override
    public LevelRule getAcceptableRevocationDataFoundConstraint(Context context, SubContext subContext) {
        return validationPolicy.getAcceptableRevocationDataFoundConstraint(context, subContext);
    }

    @Override
    public LevelRule getCRLNextUpdatePresentConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCRLNextUpdatePresentConstraint(context, subContext);
    }

    @Override
    public LevelRule getOCSPNextUpdatePresentConstraint(Context context, SubContext subContext) {
        return validationPolicy.getOCSPNextUpdatePresentConstraint(context, subContext);
    }

    @Override
    public DurationRule getRevocationFreshnessConstraint(Context context, SubContext subContext) {
        return validationPolicy.getRevocationFreshnessConstraint(context, subContext);
    }

    @Override
    public LevelRule getRevocationFreshnessNextUpdateConstraint(Context context, SubContext subContext) {
        return validationPolicy.getRevocationFreshnessNextUpdateConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateNotRevokedConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateNotRevokedConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateNotOnHoldConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateNotOnHoldConstraint(context, subContext);
    }

    @Override
    public LevelRule getRevocationIssuerNotExpiredConstraint(Context context, SubContext subContext) {
        return validationPolicy.getRevocationIssuerNotExpiredConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateNotSelfSignedConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateNotSelfSignedConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateSelfSignedConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateSelfSignedConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getTrustServiceTypeIdentifierConstraint(Context context) {
        return validationPolicy.getTrustServiceTypeIdentifierConstraint(context);
    }

    @Override
    public MultiValuesRule getTrustServiceStatusConstraint(Context context) {
        return validationPolicy.getTrustServiceStatusConstraint(context);
    }

    @Override
    public MultiValuesRule getCertificatePolicyIdsConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePolicyIdsConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificatePolicyQualificationIdsConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePolicyQualificationIdsConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificatePolicySupportedByQSCDIdsConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePolicySupportedByQSCDIdsConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateQCComplianceConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateQCComplianceConstraint(context, subContext);
    }

    @Override
    public ValueRule getCertificateQcEuLimitValueCurrencyConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateQcEuLimitValueCurrencyConstraint(context, subContext);
    }

    @Override
    public NumericValueRule getCertificateMinQcEuLimitValueConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateMinQcEuLimitValueConstraint(context, subContext);
    }

    @Override
    public NumericValueRule getCertificateMinQcEuRetentionPeriodConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateMinQcEuRetentionPeriodConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateQcSSCDConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateQcSSCDConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateQcEuPDSLocationConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateQcEuPDSLocationConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateQcTypeConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateQcTypeConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateQcCCLegislationConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateQcCCLegislationConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateIssuedToNaturalPersonConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateIssuedToNaturalPersonConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateIssuedToLegalPersonConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateIssuedToLegalPersonConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateSemanticsIdentifierConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateSemanticsIdentifierConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificatePS2DQcTypeRolesOfPSPConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePS2DQcTypeRolesOfPSPConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificatePS2DQcCompetentAuthorityNameConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePS2DQcCompetentAuthorityNameConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificatePS2DQcCompetentAuthorityIdConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePS2DQcCompetentAuthorityIdConstraint(context, subContext);
    }

    @Override
    public LevelRule getSigningCertificateRecognitionConstraint(Context context) {
        return validationPolicy.getSigningCertificateRecognitionConstraint(context);
    }

    @Override
    public LevelRule getSigningCertificateAttributePresentConstraint(Context context) {
        return validationPolicy.getSigningCertificateAttributePresentConstraint(context);
    }

    @Override
    public LevelRule getUnicitySigningCertificateAttributeConstraint(Context context) {
        return validationPolicy.getUnicitySigningCertificateAttributeConstraint(context);
    }

    @Override
    public LevelRule getSigningCertificateDigestValuePresentConstraint(Context context) {
        return validationPolicy.getSigningCertificateDigestValuePresentConstraint(context);
    }

    @Override
    public LevelRule getSigningCertificateDigestValueMatchConstraint(Context context) {
        return validationPolicy.getSigningCertificateDigestValueMatchConstraint(context);
    }

    @Override
    public LevelRule getSigningCertificateIssuerSerialMatchConstraint(Context context) {
        return validationPolicy.getSigningCertificateIssuerSerialMatchConstraint(context);
    }

    @Override
    public LevelRule getKeyIdentifierPresent(Context context) {
        return validationPolicy.getKeyIdentifierPresent(context);
    }

    @Override
    public LevelRule getKeyIdentifierMatch(Context context) {
        return validationPolicy.getKeyIdentifierMatch(context);
    }

    @Override
    public LevelRule getReferenceDataExistenceConstraint(Context context) {
        return validationPolicy.getReferenceDataExistenceConstraint(context);
    }

    @Override
    public LevelRule getReferenceDataIntactConstraint(Context context) {
        return validationPolicy.getReferenceDataIntactConstraint(context);
    }

    @Override
    public LevelRule getReferenceDataNameMatchConstraint(Context context) {
        return validationPolicy.getReferenceDataNameMatchConstraint(context);
    }

    @Override
    public LevelRule getManifestEntryObjectExistenceConstraint(Context context) {
        return validationPolicy.getManifestEntryObjectExistenceConstraint(context);
    }

    @Override
    public LevelRule getManifestEntryObjectIntactConstraint(Context context) {
        return validationPolicy.getManifestEntryObjectIntactConstraint(context);
    }

    @Override
    public LevelRule getManifestEntryObjectGroupConstraint(Context context) {
        return validationPolicy.getManifestEntryObjectGroupConstraint(context);
    }

    @Override
    public LevelRule getManifestEntryNameMatchConstraint(Context context) {
        return validationPolicy.getManifestEntryNameMatchConstraint(context);
    }

    @Override
    public LevelRule getSignatureIntactConstraint(Context context) {
        return validationPolicy.getSignatureIntactConstraint(context);
    }

    @Override
    public LevelRule getSignatureDuplicatedConstraint(Context context) {
        return validationPolicy.getSignatureDuplicatedConstraint(context);
    }

    @Override
    public LevelRule getSignerInformationStoreConstraint(Context context) {
        return validationPolicy.getSignerInformationStoreConstraint(context);
    }

    @Override
    public LevelRule getByteRangeConstraint(Context context) {
        return validationPolicy.getByteRangeConstraint(context);
    }

    @Override
    public LevelRule getByteRangeCollisionConstraint(Context context) {
        return validationPolicy.getByteRangeCollisionConstraint(context);
    }

    @Override
    public LevelRule getByteRangeAllDocumentConstraint(Context context) {
        return validationPolicy.getByteRangeAllDocumentConstraint(context);
    }

    @Override
    public LevelRule getPdfSignatureDictionaryConstraint(Context context) {
        return validationPolicy.getPdfSignatureDictionaryConstraint(context);
    }

    @Override
    public LevelRule getPdfPageDifferenceConstraint(Context context) {
        return validationPolicy.getPdfPageDifferenceConstraint(context);
    }

    @Override
    public LevelRule getPdfAnnotationOverlapConstraint(Context context) {
        return validationPolicy.getPdfAnnotationOverlapConstraint(context);
    }

    @Override
    public LevelRule getPdfVisualDifferenceConstraint(Context context) {
        return validationPolicy.getPdfVisualDifferenceConstraint(context);
    }

    @Override
    public LevelRule getDocMDPConstraint(Context context) {
        return validationPolicy.getDocMDPConstraint(context);
    }

    @Override
    public LevelRule getFieldMDPConstraint(Context context) {
        return validationPolicy.getFieldMDPConstraint(context);
    }

    @Override
    public LevelRule getSigFieldLockConstraint(Context context) {
        return validationPolicy.getSigFieldLockConstraint(context);
    }

    @Override
    public LevelRule getFormFillChangesConstraint(Context context) {
        return validationPolicy.getFormFillChangesConstraint(context);
    }

    @Override
    public LevelRule getAnnotationChangesConstraint(Context context) {
        return validationPolicy.getAnnotationChangesConstraint(context);
    }

    @Override
    public LevelRule getUndefinedChangesConstraint(Context context) {
        return validationPolicy.getUndefinedChangesConstraint(context);
    }

    @Override
    public LevelRule getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint() {
        return validationPolicy.getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint();
    }

    @Override
    public LevelRule getTimestampCoherenceConstraint() {
        return validationPolicy.getTimestampCoherenceConstraint();
    }

    @Override
    public DurationRule getTimestampDelayConstraint() {
        return validationPolicy.getTimestampDelayConstraint();
    }

    @Override
    public LevelRule getTimestampValidConstraint() {
        return validationPolicy.getTimestampValidConstraint();
    }

    @Override
    public LevelRule getTimestampTSAGeneralNamePresent() {
        return validationPolicy.getTimestampTSAGeneralNamePresent();
    }

    @Override
    public LevelRule getTimestampTSAGeneralNameContentMatch() {
        return validationPolicy.getTimestampTSAGeneralNameContentMatch();
    }

    @Override
    public LevelRule getTimestampTSAGeneralNameOrderMatch() {
        return validationPolicy.getTimestampTSAGeneralNameOrderMatch();
    }

    @Override
    public LevelRule getAtsHashIndexConstraint() {
        return validationPolicy.getAtsHashIndexConstraint();
    }

    @Override
    public LevelRule getTimestampContainerSignedAndTimestampedFilesCoveredConstraint() {
        return validationPolicy.getTimestampContainerSignedAndTimestampedFilesCoveredConstraint();
    }

    @Override
    public LevelRule getRevocationTimeAgainstBestSignatureDurationRule() {
        return validationPolicy.getRevocationTimeAgainstBestSignatureDurationRule();
    }

    @Override
    public LevelRule getEvidenceRecordValidConstraint() {
        return validationPolicy.getEvidenceRecordValidConstraint();
    }

    @Override
    public LevelRule getEvidenceRecordDataObjectExistenceConstraint() {
        return validationPolicy.getEvidenceRecordDataObjectExistenceConstraint();
    }

    @Override
    public LevelRule getEvidenceRecordDataObjectIntactConstraint() {
        return validationPolicy.getEvidenceRecordDataObjectIntactConstraint();
    }

    @Override
    public LevelRule getEvidenceRecordDataObjectFoundConstraint() {
        return validationPolicy.getEvidenceRecordDataObjectFoundConstraint();
    }

    @Override
    public LevelRule getEvidenceRecordDataObjectGroupConstraint() {
        return validationPolicy.getEvidenceRecordDataObjectGroupConstraint();
    }

    @Override
    public LevelRule getEvidenceRecordSignedFilesCoveredConstraint() {
        return validationPolicy.getEvidenceRecordSignedFilesCoveredConstraint();
    }

    @Override
    public LevelRule getEvidenceRecordContainerSignedAndTimestampedFilesCoveredConstraint() {
        return validationPolicy.getEvidenceRecordContainerSignedAndTimestampedFilesCoveredConstraint();
    }

    @Override
    public LevelRule getEvidenceRecordHashTreeRenewalConstraint() {
        return validationPolicy.getEvidenceRecordHashTreeRenewalConstraint();
    }

    @Override
    public LevelRule getCounterSignatureConstraint(Context context) {
        return validationPolicy.getCounterSignatureConstraint(context);
    }

    @Override
    public LevelRule getSignatureTimeStampConstraint(Context context) {
        return validationPolicy.getSignatureTimeStampConstraint(context);
    }

    @Override
    public LevelRule getValidationDataTimeStampConstraint(Context context) {
        return validationPolicy.getValidationDataTimeStampConstraint(context);
    }

    @Override
    public LevelRule getValidationDataRefsOnlyTimeStampConstraint(Context context) {
        return validationPolicy.getValidationDataRefsOnlyTimeStampConstraint(context);
    }

    @Override
    public LevelRule getArchiveTimeStampConstraint(Context context) {
        return validationPolicy.getArchiveTimeStampConstraint(context);
    }

    @Override
    public LevelRule getDocumentTimeStampConstraint(Context context) {
        return validationPolicy.getDocumentTimeStampConstraint(context);
    }

    @Override
    public LevelRule getTLevelTimeStampConstraint(Context context) {
        return validationPolicy.getTLevelTimeStampConstraint(context);
    }

    @Override
    public LevelRule getLTALevelTimeStampConstraint(Context context) {
        return validationPolicy.getLTALevelTimeStampConstraint(context);
    }

    @Override
    public MultiValuesRule getSignatureFormatConstraint(Context context) {
        return validationPolicy.getSignatureFormatConstraint(context);
    }

    @Override
    public MultiValuesRule getCertificateCountryConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateCountryConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateLocalityConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateLocalityConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateStateConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateStateConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateOrganizationIdentifierConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateOrganizationIdentifierConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateOrganizationNameConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateOrganizationNameConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateOrganizationUnitConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateOrganizationUnitConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateSurnameConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateSurnameConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateGivenNameConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateGivenNameConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateCommonNameConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateCommonNameConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificatePseudonymConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePseudonymConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificatePseudoUsageConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificatePseudoUsageConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateTitleConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateTitleConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getCertificateEmailConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateEmailConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateSerialNumberConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateSerialNumberConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateAuthorityInfoAccessPresentConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateAuthorityInfoAccessPresentConstraint(context, subContext);
    }

    @Override
    public CertificateApplicabilityRule getRevocationDataSkipConstraint(Context context, SubContext subContext) {
        return validationPolicy.getRevocationDataSkipConstraint(context, subContext);
    }

    @Override
    public LevelRule getCertificateRevocationInfoAccessPresentConstraint(Context context, SubContext subContext) {
        return validationPolicy.getCertificateRevocationInfoAccessPresentConstraint(context, subContext);
    }

    @Override
    public MultiValuesRule getAcceptedContainerTypesConstraint() {
        return validationPolicy.getAcceptedContainerTypesConstraint();
    }

    @Override
    public LevelRule getZipCommentPresentConstraint() {
        return validationPolicy.getZipCommentPresentConstraint();
    }

    @Override
    public MultiValuesRule getAcceptedZipCommentsConstraint() {
        return validationPolicy.getAcceptedZipCommentsConstraint();
    }

    @Override
    public LevelRule getMimeTypeFilePresentConstraint() {
        return validationPolicy.getMimeTypeFilePresentConstraint();
    }

    @Override
    public MultiValuesRule getAcceptedMimeTypeContentsConstraint() {
        return validationPolicy.getAcceptedMimeTypeContentsConstraint();
    }

    @Override
    public LevelRule getManifestFilePresentConstraint() {
        return validationPolicy.getManifestFilePresentConstraint();
    }

    @Override
    public LevelRule getSignedFilesPresentConstraint() {
        return validationPolicy.getSignedFilesPresentConstraint();
    }

    @Override
    public LevelRule getAllFilesSignedConstraint() {
        return validationPolicy.getAllFilesSignedConstraint();
    }

    @Override
    public LevelRule getFullScopeConstraint() {
        return validationPolicy.getFullScopeConstraint();
    }

    @Override
    public MultiValuesRule getAcceptablePDFAProfilesConstraint() {
        return validationPolicy.getAcceptablePDFAProfilesConstraint();
    }

    @Override
    public LevelRule getPDFACompliantConstraint() {
        return validationPolicy.getPDFACompliantConstraint();
    }

    @Override
    public boolean isEIDASConstraintPresent() {
        return validationPolicy.isEIDASConstraintPresent();
    }

    @Override
    public DurationRule getTLFreshnessConstraint() {
        return validationPolicy.getTLFreshnessConstraint();
    }

    @Override
    public LevelRule getTLWellSignedConstraint() {
        return validationPolicy.getTLWellSignedConstraint();
    }

    @Override
    public LevelRule getTLNotExpiredConstraint() {
        return validationPolicy.getTLNotExpiredConstraint();
    }

    @Override
    public MultiValuesRule getTLVersionConstraint() {
        return validationPolicy.getTLVersionConstraint();
    }

    @Override
    public LevelRule getTLStructureConstraint() {
        return validationPolicy.getTLStructureConstraint();
    }

    @Override
    public ValidationModel getValidationModel() {
        return validationPolicy.getValidationModel();
    }

}
