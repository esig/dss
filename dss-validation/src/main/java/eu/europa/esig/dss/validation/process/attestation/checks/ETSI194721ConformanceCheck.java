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
package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * This class verifies whether the issuing authority identifier is valid as per TS 119 472-1
 */
public class ETSI194721ConformanceCheck extends ChainItem<XmlSAV> {

    /** mdoc document type as defined in ISO/IEC 18013-5 */
    public static final String ISO18013_5_MDL_DOC_TYPE = "org.iso.18013.5.1.mDL";

    /** Namespace for the data elements defined in section 7.1 of ISO/IEC 18013-5  */
    public static final String ISO18013_5_NAMESPACE = "org.iso.18013.5.1";

    /** Namespace for the data elements defined in section 6.3 of ISO/IEC 23220-2  */
    public static final String ISO23220_1_NAMESPACE = "org.iso.23220.1";

    /** Namespace for the data elements defined in section 6 of ETSI TS 119 472-1  */
    public static final String ETSI_19472_1_NAMESPACE = "org.etsi.01947201.010101";

    /** attestation to check */
    private final AttestationWrapper attestation;

    /** Validation time */
    private final Date validationTime;

    /**
     * Default constructor
     *
     * @param i18nProvider
     *         {@link I18nProvider}
     * @param result
     *         {@link XmlSAV}
     * @param attestation
     *         {@link AttestationWrapper}
     * @param validationTime
     *         {@link Date}
     * @param constraint
     *         {@link LevelRule}
     */
    public ETSI194721ConformanceCheck(I18nProvider i18nProvider, XmlSAV result,
                                      AttestationWrapper attestation, Date validationTime, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.attestation = attestation;
        this.validationTime = validationTime;
    }

    @Override
    protected boolean process() {
        return checkVCTPresent()
                && checkVCTIntegrityPresent()
                && checkNowAfterNotBefore()
                && checkNowBeforeExpiration()
                && checkNowAfterAdministrativeDateIssuance()
                && checkNowBeforeAdministrativeDateExpiration()
                && checkSDJWTAdministrativeDateConformance()
                && checkSDJWTIssuingAuthorityAndCountryPresent()
                && checkMDOCNamespaceConformance()
                && checkMDOCDocumentNumberPresent()
                && checkMDOCIssuingAuthorityPresent()
                && checkNoStatusIfShortLived()
                && checkStatusIsPresentIfMandatory()
                && checkSDJWTStatusConformance();
    }

    private boolean checkVCTPresent() {
        if (AttestationProfile.SD_JWT_VC.equals(attestation.getAttestationProfile())) {
            return attestation.getVerifiableCredentialsTypeUri() != null;
        }
        return true;
    }

    private boolean checkVCTIntegrityPresent() {
        if (AttestationProfile.SD_JWT_VC.equals(attestation.getAttestationProfile())) {
            return attestation.getVerifiableCredentialsTypeIntegrityBytes() != null;
        }
        return true;
    }

    private boolean checkSDJWTIssuingAuthorityAndCountryPresent() {
        if (AttestationProfile.SD_JWT_VC.equals(attestation.getAttestationProfile())) {
            SignatureWrapper attestationSignature = attestation.getAttestationSignatures().get(0);
            CertificateWrapper signingCertificate = attestationSignature.getSigningCertificate();
            List<RelatedCertificateWrapper> relatedCertificates = attestationSignature.foundCertificates().getRelatedCertificates();

            boolean signCertPresent = signingCertificate != null && Utils.isCollectionNotEmpty(relatedCertificates)
                    && relatedCertificates.stream().anyMatch(c -> signingCertificate.getId().equals(c.getId()));
            if (signCertPresent) {
                if (signingCertificate.isQcCompliance()) {
                    return attestation.getDocumentIssuingAuthority() == null && attestation.getDocumentIssuingAuthorityCountry() == null;
                }
            } else if (attestation.getCategoryQualification().equals(AttestationQualification.QEAA)
                    || attestation.getCategoryQualification().equals(AttestationQualification.PUBEAA)) {
                // NOTE: TS 119 472-1 v1.2.1 expects a QC for a QEAA/PubEAA, but does not define how to proceed for a not QC
                // Therefore we accept any certificate in such a case
                return attestation.getDocumentIssuingAuthority() != null && attestation.getDocumentIssuingAuthorityCountry() != null;
            }
        }

        return true;
    }

    private boolean checkMDOCIssuingAuthorityPresent() {
        if (AttestationProfile.ISO_IEC_MDOC.equals(attestation.getAttestationProfile())) {
            return attestation.getDocumentIssuingAuthority() != null;
        }

        return true;
    }

    private boolean checkMDOCNamespaceConformance() {
        /*
         * EAA-6.1-02: If the attestation is a mobile driving license (mDL) (i.e. the document type of the attestation is
         * "org.iso.18013.5.1.mDL"), it:
         * 1) Shall contain data elements defined in section 7.1 of ISO/IEC 18013-5 [12] within the namespace
         * "org.iso.18013.5.1"; and
         * 2) May contain data elements defined in the present document.
         *
         * EAA-6.1-03: If the attestation is NOT a mobile driving license, it:
         * 1) Shall contain data elements defined in section 6.3 of ISO/IEC 23220-2 [13] within the namespace
         * "org.iso.23220.1";
         * 2) May contain data elements defined in the present document; and
         * 3) May contain data elements defined in another document.
         */
        if (AttestationProfile.ISO_IEC_MDOC.equals(attestation.getAttestationProfile())) {
            Set<String> namespaces = attestation.getAllClaimNamespaces();
            if (ISO18013_5_MDL_DOC_TYPE.equals(attestation.getAttestationDocumentType())) {
                if (!namespaces.contains(ISO18013_5_NAMESPACE)) {
                    return false;
                }
                if (namespaces.stream().anyMatch(n -> !ISO18013_5_NAMESPACE.equals(n) && !ETSI_19472_1_NAMESPACE.equals(n))) {
                    return false;
                }
            } else {
                if (!namespaces.contains(ISO23220_1_NAMESPACE)) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean checkMDOCDocumentNumberPresent() {
        if (AttestationProfile.ISO_IEC_MDOC.equals(attestation.getAttestationProfile())) {
            return attestation.getDocumentNumber() != null;
        }

        return true;
    }

    private boolean checkSDJWTAdministrativeDateConformance() {
        if (AttestationProfile.SD_JWT_VC == attestation.getAttestationProfile()) {
            return (attestation.getAdministrativeIssuanceDate() == null) == (attestation.getAdministrativeExpirationDate() == null);
        }

        return true;
    }

    private boolean checkNowAfterAdministrativeDateIssuance() {
        if (attestation.getAdministrativeIssuanceDate() != null) {
            return !validationTime.before(attestation.getAdministrativeIssuanceDate());
        }

        // Administrative date is optional, return true if not present
        return true;
    }

    private boolean checkNowBeforeAdministrativeDateExpiration() {
        if (attestation.getAdministrativeExpirationDate() != null) {
            return validationTime.before(attestation.getAdministrativeExpirationDate());
        }

        // Administrative date is optional, return true if not present
        return true;
    }

    private boolean checkNowAfterNotBefore() {
        return attestation.getNotBefore() != null && !validationTime.before(attestation.getNotBefore());
    }

    private boolean checkNowBeforeExpiration() {
        return attestation.getExpiration() != null && validationTime.before(attestation.getExpiration());
    }

    private boolean checkNoStatusIfShortLived() {
        if (Utils.isTrue(attestation.getShortLived())) {
            return attestation.getPayload().getStatus() == null;
        }
        return true;
    }

    private boolean checkStatusIsPresentIfMandatory() {
        if ((attestation.getCategoryQualification().equals(AttestationQualification.QEAA) || attestation.getCategoryQualification().equals(AttestationQualification.PUBEAA))
                && !Utils.isTrue(attestation.getShortLived())) {
            return attestation.getPayload().getStatus() != null;
        }

        return true;
    }

    private boolean checkSDJWTStatusConformance() {
        // TODO: lax processing until TS 119 472-1 review
//        if (EAAType.SD_JWT_VC == attestation.getType()
//                && attestation.getPayload().getStatus() != null) {
//            return attestation.getStatusUri() != null
//                    && attestation.getStatusIndex() != null
//                    && attestation.getStatusType() != null
//                    && attestation.getStatusPurpose() != null;
//        }
        return true;
    }

    @Override
    protected String buildAdditionalInfo() {
        List<String> errors = new ArrayList<>();
        if (!checkVCTPresent()) {
            errors.add(i18nProvider.getMessage(MessageTag.SDJWT_EAA_VCT_PRESENT_ANS,
                    ValidationProcessUtils.getFormattedDate(validationTime),
                    ValidationProcessUtils.getFormattedDate(attestation.getNotBefore())));
        }
        if (!checkVCTIntegrityPresent()) {
            errors.add(i18nProvider.getMessage(MessageTag.SDJWT_EAA_VCT_INT_PRESENT_ANS,
                    ValidationProcessUtils.getFormattedDate(validationTime),
                    ValidationProcessUtils.getFormattedDate(attestation.getNotBefore())));
        }
        if (!checkNowAfterNotBefore()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_NOW_BEFORE_NBF,
                    ValidationProcessUtils.getFormattedDate(validationTime),
                    ValidationProcessUtils.getFormattedDate(attestation.getNotBefore())));
        }
        if (!checkNowBeforeExpiration()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_NOW_AFTER_EXP,
                    ValidationProcessUtils.getFormattedDate(validationTime),
                    ValidationProcessUtils.getFormattedDate(attestation.getExpiration())));
        }
        if (!checkNowAfterAdministrativeDateIssuance()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_NOW_BEFORE_ADI,
                    ValidationProcessUtils.getFormattedDate(validationTime),
                    ValidationProcessUtils.getFormattedDate(attestation.getAdministrativeIssuanceDate())));
        }
        if (!checkNowBeforeAdministrativeDateExpiration()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_NOW_AFTER_ADE,
                    ValidationProcessUtils.getFormattedDate(validationTime),
                    ValidationProcessUtils.getFormattedDate(attestation.getAdministrativeExpirationDate())));
        }
        if (!checkSDJWTIssuingAuthorityAndCountryPresent()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_SDJWT_ISSUING_AUTHORITY));
        }
        if (!checkSDJWTAdministrativeDateConformance()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_AD_SDJWT_CONFORMANCE));
        }
        if (!checkMDOCNamespaceConformance()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_MDOC_NAMESPACE_CONFORMANCE));
        }
        if (!checkMDOCDocumentNumberPresent()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_MDOC_DOCUMENT_NUMBER_ABSENT));
        }
        if (!checkMDOCIssuingAuthorityPresent()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_MDOC_ISSUING_AUTHORITY));
        }
        if (!checkNoStatusIfShortLived()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_SHORT_LIVED_STATUS_PRESENT));
        }
        if (!checkStatusIsPresentIfMandatory()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_MANDATORY_STATUS_ABSENT));
        }
        if (!checkSDJWTStatusConformance()) {
            errors.add(i18nProvider.getMessage(MessageTag.EAA_REV_SDJWT_CONFORMANCE));
        }

        if (Utils.isCollectionNotEmpty(errors)) {
            return Utils.joinStrings(errors, " - ");
        }
        return null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_ETSI194721;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_ETSI194721_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.ATTESTATION_CONSTRAINTS_FAILURE;
    }

}
