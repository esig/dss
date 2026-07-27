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
package eu.europa.esig.dss.validation.process.qualification.attestation.pid;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateApprovalStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlLoTEAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateApprovalStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationPIDQualificationProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustedEntityServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustSourceList;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatus;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatusEnum;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.LoTEServiceTypeIdentifierEnum;
import eu.europa.esig.dss.enumerations.LoTETypeEnum;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.CertificateApprovalStatusAtTimeBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.AcceptableLoLoTECheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.AcceptableLoTECheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.AcceptableLoTEPresenceCheck;
import eu.europa.esig.dss.validation.process.qualification.attestation.AttestationQualificationMatrix;
import eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks.ListOfTrustedEntitiesReachedForCertificateChainCheck;
import eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks.PIDDocumentTypeAcceptableCheck;
import eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks.PIDIssuanceTrustedEntityServicesCheck;
import eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks.PIDProviderCertificateAtIssuanceTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks.PIDProviderCertificateAtValidationTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks.PIDProviderListCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedEntitiesFilterFactory;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedEntityServiceFilter;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Performs verification whether the provided token is a PID
 *
 */
public class PIDQualificationProcessBlock extends Chain<XmlValidationPIDQualificationProcess> {

    /** The attestation to be validated */
    private final AttestationWrapper attestation;

    /** The conclusion of attestation validation */
    private final XmlConclusion attestationConclusion;

    /** List of List of Trusted Entities validations */
    private final List<XmlLoTEAnalysis> loteAnalysis;

    /** Validation time */
    private final Date currentTime;

    /**
     * Default constructor
     *
     * @param i18nProvider         {@link I18nProvider}
     * @param attestation      {@link AttestationWrapper} for which qualification is to be determined
     * @param attestationConclusion {@link XmlConclusion}
     * @param loteAnalysis         a list of performed {@link XmlLoTEAnalysis}
     * @param currentTime          {@link Date}
     */
    public PIDQualificationProcessBlock(final I18nProvider i18nProvider, final AttestationWrapper attestation,
                                        final XmlConclusion attestationConclusion, final List<XmlLoTEAnalysis> loteAnalysis,
                                        final Date currentTime) {
        super(i18nProvider, new XmlValidationPIDQualificationProcess());
        this.attestation = attestation;
        this.attestationConclusion = attestationConclusion;
        this.loteAnalysis = loteAnalysis;
        this.currentTime = currentTime;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.PID_QUALIFICATION_PROCESS;
    }

    @Override
    protected void initChain() {

        if (Utils.isCollectionEmpty(attestation.getAttestationSignatures())) {
            throw new IllegalStateException("No signatures found within the attestation token!");
        }

        CertificateApprovalStatus certificateApprovalStatusAtIssuanceTime = CertificateApprovalStatusEnum.NA;
        CertificateApprovalStatus certificateApprovalStatusAtValidationTime = CertificateApprovalStatusEnum.NA;

        SignatureWrapper signature = attestation.getAttestationSignatures().get(0);
        CertificateWrapper signingCertificate = signature.getSigningCertificate();

        ChainItem<XmlValidationPIDQualificationProcess> item = firstItem = isListOfTrustedEntitiesReachedForCertificateChain(signingCertificate);

        PIDDocumentTypeAcceptableCheck pidDocumentTypeAcceptableCheck = pidDocumentTypeAcceptable();
        item = item.setNextItem(pidDocumentTypeAcceptableCheck);

        if (signingCertificate != null) {

            final Set<XmlTrustSourceList> acceptableLoTEs = new HashSet<>();

            if (signingCertificate.isListOfTrustedEntitiesReached()) {

                List<TrustedEntityServiceWrapper> originalTESs = signingCertificate.getTrustedEntityServices();

                Set<XmlTrustSourceList> listsOfLists = originalTESs.stream().map(TrustedEntityServiceWrapper::getListOfTrustedSourceList)
                        .filter(Objects::nonNull).collect(Collectors.toSet());

                Set<XmlTrustSourceList> acceptableLoLoTEs = new HashSet<>();
                for (XmlTrustSourceList listOfLists : listsOfLists) {
                    XmlLoTEAnalysis loloteAnalysis = getLoTEAnalysis(listOfLists);
                    if (loloteAnalysis != null) {
                        AcceptableLoLoTECheck<XmlValidationPIDQualificationProcess> acceptableLOTL = isAcceptableLoLoTE(loloteAnalysis);
                        item = item.setNextItem(acceptableLOTL);
                        if (acceptableLOTL.process()) {
                            acceptableLoLoTEs.add(listOfLists);
                        }
                    }
                }

                // filter TLs with a found valid set of LoLoTEs (if assigned)
                Set<XmlTrustSourceList> lotes = originalTESs.stream().filter(t -> t.getTrustedSourceList() != null &&
                                (t.getListOfTrustedSourceList() == null || acceptableLoLoTEs.contains(t.getListOfTrustedSourceList())) )
                        .map(TrustedEntityServiceWrapper::getTrustedSourceList).collect(Collectors.toSet());

                if (Utils.isCollectionNotEmpty(lotes)) {
                    for (XmlTrustSourceList lote : lotes) {
                        XmlLoTEAnalysis currentTL = getLoTEAnalysis(lote);
                        if (currentTL != null) {

                            AcceptableLoTECheck<XmlValidationPIDQualificationProcess> acceptableTL = isAcceptableLoTE(currentTL);
                            item = item.setNextItem(acceptableTL);

                            PIDProviderListCheck loteForPIDProviders = loteForPIDProviders(lote.getType());
                            item = item.setNextItem(loteForPIDProviders);

                            if (acceptableTL.process() && loteForPIDProviders.process()) {
                                acceptableLoTEs.add(lote);
                            }
                        }
                    }
                }

                item = item.setNextItem(isAcceptableLoTEPresent(acceptableLoTEs));

                if (Utils.isCollectionNotEmpty(acceptableLoTEs)) {

                    List<String> trustedSourceUrls = getTrustedSourceUrls(lotes);
                    TrustedEntityServiceFilter filter = TrustedEntitiesFilterFactory.createFilterByListUrls(trustedSourceUrls);
                    List<TrustedEntityServiceWrapper> relatedServices = filter.filter(originalTESs);

                    filter = TrustedEntitiesFilterFactory.createFilterByServiceTypeIdentifierUri(LoTEServiceTypeIdentifierEnum.PID_ISSUANCE.getUri());
                    List<TrustedEntityServiceWrapper> filteredServices = filter.filter(relatedServices);

                    item = item.setNextItem(stiForPIDIssuance(filteredServices));

                    if (Utils.isCollectionNotEmpty(filteredServices)) {
                        // assign not filtered list to ensure certificate qualification processing
                        relatedServices = filteredServices;
                    }

                    if (Utils.isCollectionNotEmpty(relatedServices)) {

                        CertificateApprovalStatusAtTimeBlock certApprovalStatusAtIssuanceBlock = getCertUsageAtIssuanceTimeBlock(signingCertificate, relatedServices);
                        XmlValidationCertificateApprovalStatus certApprovalStatusAtIssuanceResult = certApprovalStatusAtIssuanceBlock.execute();
                        result.getValidationCertificateApprovalStatus().add(certApprovalStatusAtIssuanceResult);

                        CertificateApprovalStatusAtTimeBlock certApprovalStatusAtValidationTimeBlock = getCertUsageAtValidationTimeBlock(signingCertificate, relatedServices);
                        XmlValidationCertificateApprovalStatus certApprovalStatusAtValidationTimeResult = certApprovalStatusAtValidationTimeBlock.execute();
                        result.getValidationCertificateApprovalStatus().add(certApprovalStatusAtValidationTimeResult);

                        if (pidDocumentTypeAcceptableCheck.process()) {

                            certificateApprovalStatusAtIssuanceTime = getCertificateApprovalStatus(certApprovalStatusAtIssuanceResult);
                            item = item.setNextItem(pidProviderAtIssuanceTime(certificateApprovalStatusAtIssuanceTime));

                            certificateApprovalStatusAtValidationTime = getCertificateApprovalStatus(certApprovalStatusAtValidationTimeResult);
                            item = item.setNextItem(pidProviderAtValidationTime(certificateApprovalStatusAtValidationTime));

                        }

                    }

                }

            }


        }

        determineFinalQualification(certificateApprovalStatusAtIssuanceTime, certificateApprovalStatusAtValidationTime);

    }

    private ChainItem<XmlValidationPIDQualificationProcess> isListOfTrustedEntitiesReachedForCertificateChain(CertificateWrapper signingCertificate) {
        return new ListOfTrustedEntitiesReachedForCertificateChainCheck(i18nProvider, result, signingCertificate, getFailLevelRule());
    }

    private AcceptableLoLoTECheck<XmlValidationPIDQualificationProcess> isAcceptableLoLoTE(XmlLoTEAnalysis xmlLoLoTEAnalysis) {
        return new AcceptableLoLoTECheck<>(i18nProvider, result, xmlLoLoTEAnalysis, getWarnLevelRule());
    }

    private AcceptableLoTECheck<XmlValidationPIDQualificationProcess> isAcceptableLoTE(XmlLoTEAnalysis xmlLoLoTEAnalysis) {
        return new AcceptableLoTECheck<>(i18nProvider, result, xmlLoLoTEAnalysis, getWarnLevelRule());
    }

    private ChainItem<XmlValidationPIDQualificationProcess> isAcceptableLoTEPresent(Set<XmlTrustSourceList> acceptableLoTEs) {
        return new AcceptableLoTEPresenceCheck<>(i18nProvider, result, acceptableLoTEs, getFailLevelRule());
    }

    private PIDProviderListCheck loteForPIDProviders(String loteType) {
        return new PIDProviderListCheck(i18nProvider, result, loteType, getWarnLevelRule());
    }

    private ChainItem<XmlValidationPIDQualificationProcess> stiForPIDIssuance(List<TrustedEntityServiceWrapper> relatedServices) {
        return new PIDIssuanceTrustedEntityServicesCheck(i18nProvider, result, relatedServices, getFailLevelRule());
    }

    private PIDDocumentTypeAcceptableCheck pidDocumentTypeAcceptable() {
        return new PIDDocumentTypeAcceptableCheck(i18nProvider, result, attestation, getFailLevelRule());
    }

    private ChainItem<XmlValidationPIDQualificationProcess> pidProviderAtIssuanceTime(CertificateApprovalStatus certificateApprovalStatus) {
        return new PIDProviderCertificateAtIssuanceTimeCheck(i18nProvider, result, certificateApprovalStatus, getFailLevelRule());
    }

    private ChainItem<XmlValidationPIDQualificationProcess> pidProviderAtValidationTime(CertificateApprovalStatus certificateApprovalStatus) {
        return new PIDProviderCertificateAtValidationTimeCheck(i18nProvider, result, certificateApprovalStatus, getFailLevelRule());
    }

    private XmlLoTEAnalysis getLoTEAnalysis(XmlTrustSourceList listSource) {
        if (Utils.isCollectionNotEmpty(loteAnalysis)) {
            for (XmlLoTEAnalysis xmlTLAnalysis : loteAnalysis) {
                if (Utils.areStringsEqual(listSource.getUrl(), xmlTLAnalysis.getURL())) {
                    return xmlTLAnalysis;
                }
            }
        }
        return null;
    }

    private List<String> getTrustedSourceUrls(Collection<XmlTrustSourceList> lotes) {
        if (Utils.isCollectionEmpty(lotes)) {
            return Collections.emptyList();
        }
        return lotes.stream().map(XmlTrustSourceList::getUrl).collect(Collectors.toList());
    }

    /**
     * Gets a certificate qualification determination process for validation at the certificate issuance time
     *
     * @param certificate {@link CertificateWrapper} to be verified
     * @param acceptableServices a list of {@link TrustedEntityServiceWrapper}s acceptable for the given certificate
     * @return {@link CertificateApprovalStatusAtTimeBlock}
     */
    protected CertificateApprovalStatusAtTimeBlock getCertUsageAtIssuanceTimeBlock(
            CertificateWrapper certificate, List<TrustedEntityServiceWrapper> acceptableServices) {
        return new CertificateApprovalStatusAtTimeBlock(i18nProvider, ValidationTime.CERTIFICATE_ISSUANCE_TIME, certificate,
                LoTETypeEnum.EUPIDProvidersList.getUri(), LoTEServiceTypeIdentifierEnum.PID_ISSUANCE.getUri(), acceptableServices);
    }

    /**
     * Gets a certificate qualification determination process for validation at the validation time
     *
     * @param certificate {@link CertificateWrapper} to be verified
     * @param acceptableServices a list of {@link TrustedEntityServiceWrapper}s acceptable for the given certificate
     * @return {@link CertificateApprovalStatusAtTimeBlock}
     */
    protected CertificateApprovalStatusAtTimeBlock getCertUsageAtValidationTimeBlock(
            CertificateWrapper certificate, List<TrustedEntityServiceWrapper> acceptableServices) {
        return new CertificateApprovalStatusAtTimeBlock(i18nProvider, ValidationTime.VALIDATION_TIME, currentTime, certificate,
                LoTETypeEnum.EUPIDProvidersList.getUri(), LoTEServiceTypeIdentifierEnum.PID_ISSUANCE.getUri(), acceptableServices);
    }

    private CertificateApprovalStatus getCertificateApprovalStatus(XmlValidationCertificateApprovalStatus xmlValidationCertificateApprovalStatus) {
        XmlCertificateApprovalStatus xmlCertificateApprovalStatus = xmlValidationCertificateApprovalStatus.getCertificateApprovalStatus();
        return CertificateApprovalStatus.fromDefinition(xmlCertificateApprovalStatus.getListType(), xmlCertificateApprovalStatus.getServiceTypeIdentifier(), xmlCertificateApprovalStatus.getServiceStatus());
    }

    private void determineFinalQualification(CertificateApprovalStatus certificateApprovalStatusAtIssuanceTime, CertificateApprovalStatus certificateApprovalStatusAtValidationTime) {
        CertificateApprovalStatus certificateApprovalStatus = determinedFinalCertificateApprovalStatus(certificateApprovalStatusAtIssuanceTime, certificateApprovalStatusAtValidationTime);
        AttestationQualification finalQualification = AttestationQualificationMatrix.getPIDQualification(
                attestationConclusion.getIndication(), certificateApprovalStatus);
        result.setAttestationQualification(finalQualification);
    }

    private CertificateApprovalStatus determinedFinalCertificateApprovalStatus(CertificateApprovalStatus certificateApprovalStatusAtIssuanceTime, CertificateApprovalStatus certificateApprovalStatusAtValidationTime) {
        if (certificateApprovalStatusAtIssuanceTime == certificateApprovalStatusAtValidationTime) {
            return certificateApprovalStatusAtIssuanceTime;
        }
        return null;
    }

    @Override
    protected void collectAdditionalMessages(XmlConclusion conclusion) {
        for (XmlValidationCertificateApprovalStatus certificateApprovalStatus : result.getValidationCertificateApprovalStatus()) {
            super.collectAllMessages(conclusion, certificateApprovalStatus.getConclusion());
        }
    }

}
