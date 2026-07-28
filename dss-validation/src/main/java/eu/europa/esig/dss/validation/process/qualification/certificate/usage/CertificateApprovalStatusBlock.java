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
package eu.europa.esig.dss.validation.process.qualification.certificate.usage;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateApprovalStatusProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlLoTEAnalysis;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedEntityServiceWrapper;
import eu.europa.esig.dss.diagnostic.TrustedSourceServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustSourceList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.AcceptableBuildingBlockConclusionCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.AcceptableLoLoTECheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.AcceptableLoTECheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.AcceptableLoTEPresenceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.ListTypeKnownCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedEntitiesFilterFactory;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedEntityServiceFilter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Verifies the certificate's approval status
 * 
 */
public class CertificateApprovalStatusBlock extends Chain<XmlCertificateApprovalStatusProcess> {

    /** Certificate's BasicBuildingBlock's conclusion */
    protected final XmlConclusion buildingBlocksConclusion;

    /** Validation time */
    protected final Date validationTime;

    /** The certificate to determine qualification for */
    protected final CertificateWrapper signingCertificate;

    /** List of validation results for all Trusted Lists */
    protected final List<XmlLoTEAnalysis> loteAnalysis;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param buildingBlocksConclusion {@link XmlConclusion} of BBB for the validating certificate
     * @param validationTime {@link Date} validation time
     * @param signingCertificate {@link CertificateWrapper} to be validated
     * @param loteAnalysis a list of {@link XmlLoTEAnalysis}
     */
    public CertificateApprovalStatusBlock(I18nProvider i18nProvider, XmlConclusion buildingBlocksConclusion,
                                          Date validationTime, CertificateWrapper signingCertificate,
                                          List<XmlLoTEAnalysis> loteAnalysis) {
        super(i18nProvider, new XmlCertificateApprovalStatusProcess());
        Objects.requireNonNull(validationTime, "The validationTime shall be provided!");
        Objects.requireNonNull(signingCertificate, "The signingCertificate shall be provided!");

        result.setId(signingCertificate.getId());

        this.buildingBlocksConclusion = buildingBlocksConclusion;
        this.validationTime = validationTime;
        this.signingCertificate = signingCertificate;
        this.loteAnalysis = loteAnalysis;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.CERT_USAGES;
    }

    @Override
    protected void initChain() {
        // cover incomplete cert chain / expired/ revoked certs
        ChainItem<XmlCertificateApprovalStatusProcess> item = firstItem = isAcceptableBuildingBlockConclusion(buildingBlocksConclusion);

        Set<XmlTrustSourceList> acceptableLoTEs = new HashSet<>();
        List<TrustedEntityServiceWrapper> originalTESs = signingCertificate.getTrustedEntityServices();

        if (signingCertificate.isListOfTrustedEntitiesReached()) {

            Set<XmlTrustSourceList> listsOfLists = originalTESs.stream().map(TrustedEntityServiceWrapper::getListOfTrustedSourceList)
                    .filter(Objects::nonNull).collect(Collectors.toSet());

            Set<XmlTrustSourceList> acceptableLoLoTEs = new HashSet<>();
            for (XmlTrustSourceList listOfLists : listsOfLists) {
                XmlLoTEAnalysis loloteAnalysis = getLoTEAnalysis(listOfLists);
                if (loloteAnalysis != null) {
                    AcceptableLoLoTECheck<XmlCertificateApprovalStatusProcess> acceptableLOTL = isAcceptableLoLoTE(loloteAnalysis);
                    item = item.setNextItem(acceptableLOTL);
                    if (acceptableLOTL.process()) {
                        acceptableLoLoTEs.add(listOfLists);
                    }
                }
            }

            // filter TLs with a found valid set of LOTLs (if assigned)
            Set<XmlTrustSourceList> lotes = originalTESs.stream().filter(t -> t.getTrustedSourceList() != null &&
                            (t.getListOfTrustedSourceList() == null || acceptableLoLoTEs.contains(t.getListOfTrustedSourceList())) )
                    .map(TrustedEntityServiceWrapper::getTrustedSourceList).collect(Collectors.toSet());

            if (Utils.isCollectionNotEmpty(lotes)) {
                for (XmlTrustSourceList lote : lotes) {
                    XmlLoTEAnalysis currentTL = getLoTEAnalysis(lote);
                    if (currentTL != null) {

                        AcceptableLoTECheck<XmlCertificateApprovalStatusProcess> acceptableTL = isAcceptableLoTE(currentTL);
                        item = item.setNextItem(acceptableTL);

                        item = item.setNextItem(loteTypeKnown(lote.getType()));

                        if (acceptableTL.process()) {
                            acceptableLoTEs.add(lote);
                        }
                    }
                }
            }
        }

        item = item.setNextItem(isAcceptableLoTEPresent(acceptableLoTEs));

        if (Utils.isCollectionNotEmpty(acceptableLoTEs)) {

            Map<String, List<XmlTrustSourceList>> listsBYType = mapListsByType(acceptableLoTEs);

            for (Map.Entry<String, List<XmlTrustSourceList>> entry : listsBYType.entrySet()) {
                String listTypeUri = entry.getKey();
                List<XmlTrustSourceList> lotes = entry.getValue();

                List<String> trustedSourceUrls = getTrustedSourceUrls(lotes);
                TrustedEntityServiceFilter filter = TrustedEntitiesFilterFactory.createFilterByListUrls(trustedSourceUrls);
                List<TrustedEntityServiceWrapper> relatedServices = filter.filter(originalTESs);

                List<String> applicableStiUris = getApplicableStiUris(relatedServices);

                for (String stiUri : applicableStiUris) {
                    CertificateApprovalStatusAtTimeBlock certApprovalStatusAtIssuanceBlock = getCertUsageAtIssuanceTimeBlock(listTypeUri, stiUri, relatedServices);
                    result.getValidationCertificateApprovalStatus().add(certApprovalStatusAtIssuanceBlock.execute());

                    CertificateApprovalStatusAtTimeBlock certApprovalStatusAtValidationTimeBlock = getCertUsageAtValidationTimeBlock(listTypeUri, stiUri, relatedServices);
                    result.getValidationCertificateApprovalStatus().add(certApprovalStatusAtValidationTimeBlock.execute());
                }

            }

        }

    }

    /**
     * Gets a certificate qualification determination process for validation at the certificate issuance time
     *
     * @param listTypeUri {@link String} List of Trusted Entities type URI
     * @param stiUri {@link String} containing a service type identifier URL
     * @param acceptableServices a list of {@link TrustedEntityServiceWrapper}s acceptable for the given certificate
     * @return {@link CertificateApprovalStatusAtTimeBlock}
     */
    protected CertificateApprovalStatusAtTimeBlock getCertUsageAtIssuanceTimeBlock(String listTypeUri, String stiUri, List<TrustedEntityServiceWrapper> acceptableServices) {
        return new CertificateApprovalStatusAtTimeBlock(i18nProvider, ValidationTime.CERTIFICATE_ISSUANCE_TIME, signingCertificate, listTypeUri, stiUri, acceptableServices);
    }

    /**
     * Gets a certificate qualification determination process for validation at the validation time
     *
     * @param listTypeUri {@link String} List of Trusted Entities type URI
     * @param stiUri {@link String} containing a service type identifier URL
     * @param acceptableServices a list of {@link TrustedEntityServiceWrapper}s acceptable for the given certificate
     * @return {@link CertificateApprovalStatusAtTimeBlock}
     */
    protected CertificateApprovalStatusAtTimeBlock getCertUsageAtValidationTimeBlock(String listTypeUri, String stiUri, List<TrustedEntityServiceWrapper> acceptableServices) {
        return new CertificateApprovalStatusAtTimeBlock(i18nProvider, ValidationTime.VALIDATION_TIME, validationTime, signingCertificate, listTypeUri, stiUri, acceptableServices);
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

    private Map<String, List<XmlTrustSourceList>> mapListsByType(Collection<XmlTrustSourceList> trustSourceLists) {
        Map<String, List<XmlTrustSourceList>> result = new HashMap<>();
        for (XmlTrustSourceList trustSourceList : trustSourceLists) {
            List<XmlTrustSourceList> list = result.computeIfAbsent(trustSourceList.getType(), v -> new ArrayList<>());
            list.add(trustSourceList);
        }
        return result;
    }

    private List<String> getApplicableStiUris(List<TrustedEntityServiceWrapper> services) {
        if (Utils.isCollectionEmpty(services)) {
            return Collections.emptyList();
        }
        return services.stream().map(TrustedSourceServiceWrapper::getType).collect(Collectors.toList());
    }

    private List<String> getTrustedSourceUrls(Collection<XmlTrustSourceList> lotes) {
        if (Utils.isCollectionEmpty(lotes)) {
            return Collections.emptyList();
        }
        return lotes.stream().map(XmlTrustSourceList::getUrl).collect(Collectors.toList());
    }

    @Override
    protected void addAdditionalInfo() {
        setIndication();
    }

    private void setIndication() {
        XmlConclusion conclusion = result.getConclusion();
        if (conclusion != null) {
            if (Utils.isCollectionNotEmpty(conclusion.getErrors())) {
                conclusion.setIndication(Indication.FAILED);
            } else if (Utils.isCollectionNotEmpty(conclusion.getWarnings())) {
                conclusion.setIndication(Indication.INDETERMINATE);
            } else {
                conclusion.setIndication(Indication.PASSED);
            }
        }
    }

    private AcceptableLoLoTECheck<XmlCertificateApprovalStatusProcess> isAcceptableLoLoTE(XmlLoTEAnalysis xmlLoLoTEAnalysis) {
        return new AcceptableLoLoTECheck<>(i18nProvider, result, xmlLoLoTEAnalysis, getWarnLevelRule());
    }

    private AcceptableLoTECheck<XmlCertificateApprovalStatusProcess> isAcceptableLoTE(XmlLoTEAnalysis xmlLoTEAnalysis) {
        return new AcceptableLoTECheck<>(i18nProvider, result, xmlLoTEAnalysis, getWarnLevelRule());
    }

    private ChainItem<XmlCertificateApprovalStatusProcess> loteTypeKnown(String loteType) {
        return new ListTypeKnownCheck(i18nProvider, result, loteType, getWarnLevelRule());
    }

    private ChainItem<XmlCertificateApprovalStatusProcess> isAcceptableLoTEPresent(Set<XmlTrustSourceList> acceptableLoTEs) {
        return new AcceptableLoTEPresenceCheck<>(i18nProvider, result, acceptableLoTEs, getFailLevelRule());
    }

    private ChainItem<XmlCertificateApprovalStatusProcess> isAcceptableBuildingBlockConclusion(XmlConclusion buildingBlocksConclusion) {
        return new AcceptableBuildingBlockConclusionCheck<>(i18nProvider, result, buildingBlocksConclusion, getWarnLevelRule());
    }

}
