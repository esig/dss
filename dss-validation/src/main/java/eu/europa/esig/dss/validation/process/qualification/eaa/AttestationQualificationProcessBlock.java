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
package eu.europa.esig.dss.validation.process.qualification.eaa;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationEAAQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.EAACategory;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.GrantedStatusCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.RelatedToMraEnactedTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.AttestationCategoryForEAAPresenceCheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.AttestationCategoryForPubEAACheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.AttestationCategoryForQEAACheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.AttestationIssuerQcPSBPresentCheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.AttestationQualifiedSignatureOrSealCheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.QEAACheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableListOfTrustedListsCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListPresenceCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.TrustedListReachedForCertificateChainCheck;
import eu.europa.esig.dss.validation.process.qualification.timestamp.checks.GrantedStatusAtTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServicesFilterFactory;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Performs validation of an EAA according to the EAA types defined in Regulation EU 2024/1183 (eIDAS 2.0)
 *
 */
public class AttestationQualificationProcessBlock extends Chain<XmlValidationEAAQualificationProcess> {

    /** The EAA to be validated */
    private final AttestationWrapper eaa;

    /** The conclusion of EAA validation */
    private final XmlConclusion eaaConclusion;

    /** Map of signature validation processes */
    private final Map<String, XmlSignature> signatureMap;

    /** The list of all TL analyses */
    private final List<XmlTLAnalysis> tlAnalysis;

    /** Validation time */
    private final Date currentTime;

    /**
     * Default constructor
     *
     * @param i18nProvider         {@link I18nProvider}
     * @param eaa      {@link AttestationWrapper} for which qualification is to be determined
     * @param eaaConclusion {@link XmlConclusion}
     * @param signatureMap         a map of signature validations
     * @param tlAnalysis           a list of performed {@link XmlTLAnalysis}
     * @param currentTime          {@link Date}
     */
    public AttestationQualificationProcessBlock(final I18nProvider i18nProvider, final AttestationWrapper eaa,
                                                final XmlConclusion eaaConclusion, final Map<String, XmlSignature> signatureMap,
                                                final List<XmlTLAnalysis> tlAnalysis, final Date currentTime) {
        super(i18nProvider, new XmlValidationEAAQualificationProcess());
        this.eaa = eaa;
        this.eaaConclusion = eaaConclusion;
        this.signatureMap = signatureMap;
        this.tlAnalysis = tlAnalysis;
        this.currentTime = currentTime;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.EAA_QUALIFICATION_PROCESS;
    }

    @Override
    protected void initChain() {

        if (Utils.isCollectionEmpty(eaa.getEAASignatures())) {
            throw new IllegalStateException("No signatures found within the EAA token!");
        }

        SignatureWrapper signature = eaa.getEAASignatures().get(0);
        CertificateWrapper signingCertificate = signature.getSigningCertificate();

        ChainItem<XmlValidationEAAQualificationProcess> item = firstItem = isTrustedListReachedForCertificateChain(signingCertificate);

        item = item.setNextItem(categoryPresent());

        AttestationQualification claimedQualification = getClaimedQualification();

        if (AttestationQualification.QEAA == claimedQualification) {

            item = item.setNextItem(categoryForQEAA());

        } else if (AttestationQualification.PUBEAA == claimedQualification) {

            item = item.setNextItem(categoryForPubEAA());

        }

        SignatureQualification signatureQualification = SignatureQualification.NA;

        if (signingCertificate != null) {

            if (signingCertificate.isTrustedListReached()) {

                final Set<String> acceptableTLUrls = new HashSet<>();

                List<TrustServiceWrapper> originalTSPs = signingCertificate.getTrustServices();

                Set<String> listOfTrustedListUrls = originalTSPs.stream().filter(t -> t.getListOfTrustedLists() != null)
                        .map(t -> t.getListOfTrustedLists().getUrl()).collect(Collectors.toSet());

                Set<String> acceptableLOTLUrls = new HashSet<>();
                for (String lotlURL : listOfTrustedListUrls) {
                    XmlTLAnalysis lotlAnalysis = getTLAnalysis(lotlURL);
                    if (lotlAnalysis != null) {
                        AcceptableListOfTrustedListsCheck<XmlValidationEAAQualificationProcess> acceptableLOTL = isAcceptableLOTL(lotlAnalysis);
                        item = item.setNextItem(acceptableLOTL);
                        if (acceptableLOTL.process()) {
                            acceptableLOTLUrls.add(lotlURL);
                        }
                    }
                }

                // filter TLs with a found valid set of LOTLs (if assigned)
                Set<String> trustedListUrls = originalTSPs.stream().filter(t -> t.getTrustedList() != null &&
                                (t.getListOfTrustedLists() == null || acceptableLOTLUrls.contains(t.getListOfTrustedLists().getUrl())))
                        .map(t -> t.getTrustedList().getUrl()).collect(Collectors.toSet());

                if (Utils.isCollectionNotEmpty(trustedListUrls)) {
                    for (String tlURL : trustedListUrls) {
                        XmlTLAnalysis currentTL = getTLAnalysis(tlURL);
                        if (currentTL != null) {
                            AcceptableTrustedListCheck<XmlValidationEAAQualificationProcess> acceptableTL = isAcceptableTL(currentTL);
                            item = item.setNextItem(acceptableTL);
                            if (acceptableTL.process()) {
                                acceptableTLUrls.add(tlURL);
                            }
                        }
                    }
                }

                item = item.setNextItem(isAcceptableTLPresent(acceptableTLUrls));

                if (Utils.isCollectionNotEmpty(acceptableTLUrls)) {

                    TrustServiceFilter filter = TrustServicesFilterFactory.createFilterByUrls(acceptableTLUrls);
                    List<TrustServiceWrapper> filteredServices = filter.filter(originalTSPs);

                    // Execute only for Trusted Lists with defined MRA
                    if (isMRAEnactedForTrustedList(filteredServices)) {
                        filter = TrustServicesFilterFactory.createMRAEnactedFilter();
                        filteredServices = filter.filter(filteredServices);

                        filter = TrustServicesFilterFactory.createFilterByMRAEquivalenceStartingDate(currentTime);
                        filteredServices = filter.filter(filteredServices);

                        item = firstItem = hasMraEnactedTrustService(filteredServices);
                    }

                    // TODO : add filter for EAA and Pub-EAA ?

                    if (AttestationQualification.QEAA == claimedQualification) {

                        // 1. filter by service for EAA/Q
                        filter = TrustServicesFilterFactory.createFilterByQEAA();
                        filteredServices = filter.filter(filteredServices);

                        item = item.setNextItem(hasQEAA(filteredServices));

                    }

                    // 2. filter by granted
                    filter = TrustServicesFilterFactory.createFilterByGranted();
                    filteredServices = filter.filter(filteredServices);

                    item = item.setNextItem(hasGrantedStatus(filteredServices));

                    // 3. filter by date (validation time)
                    filter = TrustServicesFilterFactory.createFilterByDate(currentTime);
                    filteredServices = filter.filter(filteredServices);

                    item = item.setNextItem(hasGrantedStatusAtValidationTime(filteredServices));

                    if (Utils.isCollectionEmpty(filteredServices)) {
                        claimedQualification = toNotQualifiedEAA(claimedQualification);
                    }

                }

            }

            XmlSignature xmlSignature = signatureMap.get(signature.getId());
            if (xmlSignature == null) {
                throw new IllegalStateException(String.format("Signature validation is not found for Id '%s'", signature.getId()));
            }
            XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
            if (validationSignatureQualification == null) {
                throw new IllegalStateException(String.format("Signature qualification validation is not found for Id '%s'", signature.getId()));
            }

            signatureQualification = validationSignatureQualification.getSignatureQualification();

            if (AttestationQualification.QEAA == claimedQualification || AttestationQualification.PUBEAA == claimedQualification) {

                item = item.setNextItem(isSignatureQualificationStatusAcceptable(signature, signatureQualification));

            }

            if (AttestationQualification.PUBEAA == claimedQualification) {

                AttestationIssuerQcPSBPresentCheck psbEaa = psbEaa(signingCertificate);
                item = item.setNextItem(psbEaa);

                if (!psbEaa.process()) {
                    claimedQualification = toNotQualifiedEAA(claimedQualification);
                }

            }

        }

        determineFinalQualification(claimedQualification, signatureQualification);

    }

    private ChainItem<XmlValidationEAAQualificationProcess> isTrustedListReachedForCertificateChain(CertificateWrapper signingCertificate) {
        return new TrustedListReachedForCertificateChainCheck<>(i18nProvider, result, signingCertificate, getFailLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> categoryPresent() {
        return new AttestationCategoryForEAAPresenceCheck(i18nProvider, result, eaa, getInfoLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> categoryForQEAA() {
        return new AttestationCategoryForQEAACheck(i18nProvider, result, eaa, getFailLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> categoryForPubEAA() {
        return new AttestationCategoryForPubEAACheck(i18nProvider, result, eaa, getFailLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> isSignatureQualificationStatusAcceptable(
            SignatureWrapper signature, SignatureQualification signatureQualification) {
        return new AttestationQualifiedSignatureOrSealCheck(i18nProvider, result, signature, signatureQualification, getFailLevelRule());
    }

    private AcceptableListOfTrustedListsCheck<XmlValidationEAAQualificationProcess> isAcceptableLOTL(XmlTLAnalysis xmlLOTLAnalysis) {
        return new AcceptableListOfTrustedListsCheck<>(i18nProvider, result, xmlLOTLAnalysis, getWarnLevelRule());
    }

    private AcceptableTrustedListCheck<XmlValidationEAAQualificationProcess> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
        return new AcceptableTrustedListCheck<>(i18nProvider, result, xmlTLAnalysis, getWarnLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> isAcceptableTLPresent(Set<String> acceptableUrls) {
        return new AcceptableTrustedListPresenceCheck<>(i18nProvider, result, acceptableUrls, getFailLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> hasMraEnactedTrustService(List<TrustServiceWrapper> services) {
        return new RelatedToMraEnactedTrustServiceCheck<>(i18nProvider, result, services, getWarnLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> hasQEAA(List<TrustServiceWrapper> services) {
        return new QEAACheck(i18nProvider, result, services, getWarnLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> hasGrantedStatus(List<TrustServiceWrapper> services) {
        return new GrantedStatusCheck<>(i18nProvider, result, services, getFailLevelRule());
    }

    private ChainItem<XmlValidationEAAQualificationProcess> hasGrantedStatusAtValidationTime(List<TrustServiceWrapper> services) {
        return new GrantedStatusAtTimeCheck<>(i18nProvider, result, services, ValidationTime.VALIDATION_TIME, getFailLevelRule());
    }

    private AttestationIssuerQcPSBPresentCheck psbEaa(CertificateWrapper certificateWrapper) {
        return new AttestationIssuerQcPSBPresentCheck(i18nProvider, result, certificateWrapper, getWarnLevelRule());
    }

    private boolean isMRAEnactedForTrustedList(List<TrustServiceWrapper> trustServices) {
        for (TrustServiceWrapper trustService : trustServices) {
            if (Utils.isTrue(trustService.getTrustedList().isMra())) {
                return true;
            }
        }
        return false;
    }

    private XmlTLAnalysis getTLAnalysis(String url) {
        for (XmlTLAnalysis xmlTLAnalysis : tlAnalysis) {
            if (Utils.areStringsEqual(url, xmlTLAnalysis.getURL())) {
                return xmlTLAnalysis;
            }
        }
        return null;
    }

    private AttestationQualification getClaimedQualification() {
        String eaaCategory = eaa.getCategory();
        if (EAACategory.EU_QEAA.getUrn().equals(eaaCategory)) {
            return AttestationQualification.QEAA;
        } else if (EAACategory.EU_PUBEAA.getUrn().equals(eaaCategory)) {
            return AttestationQualification.PUBEAA;
        } else if (eaaCategory == null) {
            /*
             * EAA-5.2.2.1-01: SD-JWT VC EAAs issued by EAAs issuers registered in the European Union,
             * which are neither SD-JWT VC QEAAs nor SD-JWT VC PuB-EAAs, shall not include the category claim.
             */
            return AttestationQualification.EAA;
        } else {
            return AttestationQualification.UNKNOWN;
        }
    }

    private AttestationQualification toNotQualifiedEAA(AttestationQualification qualification) {
        if (AttestationQualification.QEAA == qualification || AttestationQualification.PUBEAA == qualification) {
            return AttestationQualification.EAA;
        }
        return qualification;
    }

    private void determineFinalQualification(AttestationQualification claimedQualification, SignatureQualification signatureQualification) {
        AttestationQualification finalQualification = AttestationQualificationMatrix.getEAAQualification(
                eaaConclusion.getIndication(), claimedQualification, signatureQualification);
        result.setEAAQualification(finalQualification);
    }

}
