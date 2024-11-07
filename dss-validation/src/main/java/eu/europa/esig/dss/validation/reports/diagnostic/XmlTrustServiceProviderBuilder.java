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
package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateContentEquivalence;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRACertificateMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRATrustServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryQcStatementsMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryTrustServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQualifier;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceEquivalenceInformation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.AdditionalServiceInformation;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.model.timedependent.MutableTimeDependentValues;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.tsl.CertificateContentEquivalence;
import eu.europa.esig.dss.model.tsl.Condition;
import eu.europa.esig.dss.model.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.MRA;
import eu.europa.esig.dss.model.tsl.QCStatementOids;
import eu.europa.esig.dss.model.tsl.ServiceEquivalence;
import eu.europa.esig.dss.model.tsl.ServiceTypeASi;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.QcStatementUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class is used to build a {@code XmlTrustServiceProvider} object instance
 *
 */
public class XmlTrustServiceProviderBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(XmlTrustServiceProviderBuilder.class);

    /**
     * The map of certificates identifiers and their corresponding XML representations
     */
    private final Map<String, XmlCertificate> xmlCertsMap;

    /**
     * The map of Trusted Lists
     */
    private final Map<String, XmlTrustedList> xmlTrustedListsMap;

    /**
     * The map between Trusted List identifiers and corresponding {@code TLInfo}
     */
    private final Map<String, TLInfo> tlInfoMap;

    /**
     * Builder for QcStatements
     */
    private final XmlQcStatementsBuilder qcStatementsBuilder = new XmlQcStatementsBuilder();

    /**
     * Default constructor
     *
     * @param xmlCertsMap a map of certificate identifiers and corresponding XML representations
     * @param xmlTrustedListsMap a map of trusted list identifiers and corresponding XML representations
     * @param tlInfoMap a map of trusted list identifiers and corresponding {@link TLInfo}s
     */
    public XmlTrustServiceProviderBuilder(final Map<String, XmlCertificate> xmlCertsMap,
                                            final Map<String, XmlTrustedList> xmlTrustedListsMap,
                                            final Map<String, TLInfo> tlInfoMap) {
        this.xmlCertsMap = xmlCertsMap;
        this.xmlTrustedListsMap = xmlTrustedListsMap;
        this.tlInfoMap = tlInfoMap;
    }

    /**
     * This method builds a list of {@link XmlTrustServiceProvider}s corresponding to the given {@code CertificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get a list of {@link XmlTrustServiceProvider}s
     * @param relatedTrustServices a map of trust anchor {@link CertificateToken}s and their corresponding trusted services
     * @return a list of {@link XmlTrustServiceProvider}s
     */
    public List<XmlTrustServiceProvider> build(CertificateToken certificateToken,
                                               Map<CertificateToken, List<TrustProperties>> relatedTrustServices) {
        List<XmlTrustServiceProvider> result = new ArrayList<>();
        for (Map.Entry<CertificateToken, List<TrustProperties>> entry : relatedTrustServices.entrySet()) {
            CertificateToken trustedCert = entry.getKey();
            List<TrustProperties> services = entry.getValue();

            Map<TrustServiceProvider, List<TrustProperties>> servicesByProviders = classifyByServiceProvider(services);

            for (Map.Entry<TrustServiceProvider, List<TrustProperties>> servicesByProvider : servicesByProviders
                    .entrySet()) {

                List<TrustProperties> trustServices = servicesByProvider.getValue();
                if (Utils.isCollectionNotEmpty(trustServices)) {
                    result.add(getXmlTrustServiceProvider(certificateToken, trustServices, trustedCert));
                }
            }

        }
        return Collections.unmodifiableList(result);
    }

    private Map<TrustServiceProvider, List<TrustProperties>> classifyByServiceProvider(
            List<TrustProperties> trustPropertiesList) {
        Map<TrustServiceProvider, List<TrustProperties>> servicesByProviders = new HashMap<>();
        if (Utils.isCollectionNotEmpty(trustPropertiesList)) {
            for (TrustProperties trustProperties : trustPropertiesList) {
                TrustServiceProvider currentTrustServiceProvider = trustProperties.getTrustServiceProvider();
                List<TrustProperties> list = servicesByProviders.computeIfAbsent(currentTrustServiceProvider, k -> new ArrayList<>());
                list.add(trustProperties);
            }
        }
        return servicesByProviders;
    }

    private XmlTrustServiceProvider getXmlTrustServiceProvider(CertificateToken certificateToken, List<TrustProperties> trustServices,
                                                                   CertificateToken trustAnchor) {
        TrustProperties trustProperties = trustServices.iterator().next();

       final XmlTrustServiceProvider result = new XmlTrustServiceProvider();

        LOTLInfo lotlInfo = trustProperties.getLOTLInfo();
        if (lotlInfo != null) {
            XmlTrustedList xmlLOTL = xmlTrustedListsMap.get(lotlInfo.getDSSIdAsString());
            if (xmlLOTL == null) {
                throw new IllegalStateException(String.format("LOTL with Id '%s' has not been found! " +
                        "Please verify TrustedListsCertificateSource contains TLValidationSummary.", lotlInfo.getDSSIdAsString()));
            }
            result.setLOTL(xmlLOTL);
        }
        TLInfo tlInfo = trustProperties.getTLInfo();
        if (tlInfo != null) {
            XmlTrustedList xmlTL = xmlTrustedListsMap.get(tlInfo.getDSSIdAsString());
            if (xmlTL == null) {
                throw new IllegalStateException(String.format("TL with Id '%s' has not been found! " +
                        "Please verify TrustedListsCertificateSource contains TLValidationSummary.", tlInfo.getDSSIdAsString()));
            }
            result.setTL(xmlTL);
        }

        TrustServiceProvider tsp = trustProperties.getTrustServiceProvider();
        result.setTSPNames(getLangAndValues(tsp.getNames()));
        result.setTSPTradeNames(getLangAndValues(tsp.getTradeNames()));
        result.setTSPRegistrationIdentifiers(tsp.getRegistrationIdentifiers());

        result.setTrustServices(buildXmlTrustServicesList(certificateToken, trustServices, trustAnchor));

        return result;
    }

    private List<XmlLangAndValue> getLangAndValues(Map<String, List<String>> map) {
        if (Utils.isMapNotEmpty(map)) {
            List<XmlLangAndValue> result = new ArrayList<>();
            for (Map.Entry<String, List<String>> entry : map.entrySet()) {
                String lang = entry.getKey();
                for (String value : entry.getValue()) {
                    XmlLangAndValue langAndValue = new XmlLangAndValue();
                    langAndValue.setLang(lang);
                    langAndValue.setValue(value);
                    result.add(langAndValue);
                }
            }
            return result;
        }
        return null;
    }

    private List<XmlTrustService> buildXmlTrustServicesList(CertificateToken certToken, List<TrustProperties> trustServices,
                                                                CertificateToken trustAnchor) {
        List<XmlTrustService> result = new ArrayList<>();

        for (TrustProperties trustProperties : trustServices) {
            TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService =
                    trustProperties.getTrustService();
            List<TrustServiceStatusAndInformationExtensions> serviceStatusAfterOfEqualsCertIssuance =
                    trustService.getAfter(certToken.getNotBefore());
            if (Utils.isCollectionNotEmpty(serviceStatusAfterOfEqualsCertIssuance)) {
                for (TrustServiceStatusAndInformationExtensions serviceInfoStatus : serviceStatusAfterOfEqualsCertIssuance) {
                    MRA mra = getMRA(trustProperties);
                    if (mra != null) {
                        result.addAll(buildXmlTrustServicesWithMRA(serviceInfoStatus, certToken, trustAnchor, mra));
                    } else {
                        result.add(getXmlTrustService(serviceInfoStatus, certToken, trustAnchor));
                    }
                }
            }
        }
        return Collections.unmodifiableList(result);
    }

    private MRA getMRA(TrustProperties trustProperties) {
        if (trustProperties.getTLInfo() != null) {
            TLInfo tlInfo = tlInfoMap.get(trustProperties.getTLInfo().getDSSIdAsString());
            if (tlInfo != null && tlInfo.getOtherTSLPointer() != null) {
                // may be null when no TLValidationJob is used
                return tlInfo.getOtherTSLPointer().getMra();
            }
        }
        return null;
    }

    private XmlTrustService getXmlTrustService(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                   CertificateToken certToken, CertificateToken trustAnchor) {
        XmlTrustService trustService = new XmlTrustService();

        trustService.setServiceDigitalIdentifier(xmlCertsMap.get(trustAnchor.getDSSIdAsString()));
        trustService.setServiceNames(getLangAndValues(serviceInfoStatus.getNames()));
        trustService.setServiceType(serviceInfoStatus.getType());
        trustService.setStatus(serviceInfoStatus.getStatus());
        trustService.setStartDate(serviceInfoStatus.getStartDate());
        trustService.setEndDate(serviceInfoStatus.getEndDate());

        List<XmlQualifier> qualifiers = getQualifiers(serviceInfoStatus, certToken);
        if (Utils.isCollectionNotEmpty(qualifiers)) {
            trustService.setCapturedQualifiers(qualifiers);
        }

        List<String> additionalServiceInfoUris = serviceInfoStatus.getAdditionalServiceInfoUris();
        if (Utils.isCollectionNotEmpty(additionalServiceInfoUris)) {
            trustService.setAdditionalServiceInfoUris(additionalServiceInfoUris);
        }

        List<String> serviceSupplyPoints = serviceInfoStatus.getServiceSupplyPoints();
        if (Utils.isCollectionNotEmpty(serviceSupplyPoints)) {
            trustService.setServiceSupplyPoints(serviceSupplyPoints);
        }

        trustService.setExpiredCertsRevocationInfo(serviceInfoStatus.getExpiredCertsRevocationInfo());

        return trustService;
    }

    /**
     * Retrieves all the qualifiers for which the corresponding conditionEntry is true.
     *
     * @param serviceInfoStatus {@link TrustServiceStatusAndInformationExtensions}
     * @param certificateToken {@link CertificateToken}
     * @return a list of {@link XmlQualifier}
     */
    private List<XmlQualifier> getQualifiers(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                             CertificateToken certificateToken) {
        LOG.trace("--> GET_QUALIFIERS()");
        final List<XmlQualifier> list = new ArrayList<>();
        final List<ConditionForQualifiers> conditionsForQualifiers = serviceInfoStatus.getConditionsForQualifiers();
        if (Utils.isCollectionNotEmpty(conditionsForQualifiers)) {
            for (ConditionForQualifiers conditionForQualifiers : conditionsForQualifiers) {
                Condition condition = conditionForQualifiers.getCondition();
                if (condition.check(certificateToken)) {
                    for (String qualifier : conditionForQualifiers.getQualifiers()) {
                        list.add(getXmlQualifier(qualifier, conditionForQualifiers.isCritical()));
                    }
                }
            }
        }
        return list;
    }

    private XmlQualifier getXmlQualifier(String value, boolean critical) {
        final XmlQualifier xmlQualifier = new XmlQualifier();
        xmlQualifier.setValue(value);
        xmlQualifier.setCritical(critical);
        return xmlQualifier;
    }

    private List<XmlTrustService> buildXmlTrustServicesWithMRA(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus, CertificateToken certToken,
            CertificateToken trustAnchor, MRA mra) {
        if (Utils.isCollectionNotEmpty(serviceInfoStatus.getAdditionalServiceInfoUris())) {
            List<XmlTrustService> result = new ArrayList<>();
            for (String aSI : serviceInfoStatus.getAdditionalServiceInfoUris()) {
                TrustServiceStatusAndInformationExtensions serviceInfoStatusCopy =
                        new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder(serviceInfoStatus)
                                .setAdditionalServiceInfoUris(Collections.singletonList(aSI)).build();
                result.addAll(getXmlTrustServicesForMRA(serviceInfoStatusCopy, certToken, trustAnchor, mra));
            }
            return result;

        } else {
            return getXmlTrustServicesForMRA(serviceInfoStatus, certToken, trustAnchor, mra);
        }
    }

    private List<XmlTrustService> getXmlTrustServicesForMRA(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                         CertificateToken certToken, CertificateToken trustAnchor, MRA mra) {
        List<MutableTimeDependentValues<ServiceEquivalence>> mraEquivalences = getMRAServiceEquivalences(serviceInfoStatus, certToken, mra);
        boolean enactedMra = Utils.isCollectionNotEmpty(mraEquivalences);
        if (enactedMra) {
            if (mraEquivalences.size() == 1) {
                MutableTimeDependentValues<ServiceEquivalence> serviceEquivalenceValues = mraEquivalences.iterator().next();
                LOG.info("MRA equivalence is applied for a Trusted Service : '{}'",
                        serviceEquivalenceValues.getLatest().getLegalInfoIdentifier());

                List<XmlTrustService> result = new ArrayList<>();

                List<ServiceEquivalence> serviceEquivalenceList = serviceEquivalenceValues.getAfter(certToken.getNotBefore());
                for (ServiceEquivalence serviceEquivalence : serviceEquivalenceList) {
                    // shall be computed before translation
                    TrustServiceStatusAndInformationExtensions equivalent = getEquivalent(serviceInfoStatus, serviceEquivalence);

                    XmlTrustService xmlTrustService = getXmlTrustService(equivalent, certToken, trustAnchor);
                    xmlTrustService.setMRATrustServiceMapping(getXmlMRATrustServiceMapping(serviceInfoStatus, certToken, serviceEquivalence));
                    xmlTrustService.setEnactedMRA(serviceEquivalence.getStatus().isEnacted());
                    result.add(xmlTrustService);
                }
                translateCertificate(certToken, serviceEquivalenceList);

                return result;

            } else {
                LOG.warn("More than one MRA equivalence found for a Trusted Service! MRA rules are not applied!");
            }
        }

        return Collections.singletonList(getXmlTrustService(serviceInfoStatus, certToken, trustAnchor));
    }

    private List<MutableTimeDependentValues<ServiceEquivalence>> getMRAServiceEquivalences(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                               CertificateToken certToken, MRA mra) {
        LOG.debug("MRA");
        final List<MutableTimeDependentValues<ServiceEquivalence>> equivalences = new ArrayList<>();
        for (MutableTimeDependentValues<ServiceEquivalence> serviceEquivalenceList : mra.getServiceEquivalence()) {
            // filter TrustServices that can be potentially applied to the validation
            for (ServiceEquivalence serviceEquivalence : serviceEquivalenceList.getAfter(certToken.getNotBefore())) {
                if (check(serviceInfoStatus, serviceEquivalence)) {
                    equivalences.add(serviceEquivalenceList);
                    break;
                }
            }
        }
        return equivalences;
    }

    private boolean check(TrustServiceStatusAndInformationExtensions serviceInfoStatus, ServiceEquivalence serviceEquivalence) {
        if (!checkServiceTypeAsiEquivalence(serviceInfoStatus, serviceEquivalence.getTypeAsiEquivalence())) {
            return false;
        }
        Map<List<String>, List<String>> statusEquivalence = serviceEquivalence.getStatusEquivalence();
        if (!checkStatusEquivalence(serviceInfoStatus, statusEquivalence)) {
            return false;
        }
        return true;
    }

    private boolean checkServiceTypeAsiEquivalence(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                   Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalenceMap) {
        for (ServiceTypeASi typeAsiEquivalence : typeAsiEquivalenceMap.keySet()) {
            if (checkServiceTypeASi(serviceInfoStatus, typeAsiEquivalence)) {
                return true;
            }
        }
        return false;
    }

    private boolean checkServiceTypeASi(TrustServiceStatusAndInformationExtensions serviceInfoStatus, ServiceTypeASi serviceTypeASi) {
        return serviceInfoStatus.getType().equals(serviceTypeASi.getType()) &&
                (serviceTypeASi.getAsi() == null || serviceInfoStatus.getAdditionalServiceInfoUris().contains(serviceTypeASi.getAsi()));
    }

    private boolean checkCertTypeAsiEquivalence(CertificateToken certToken,
                                                Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalenceMap) {
        XmlCertificate xmlCertificate = xmlCertsMap.get(certToken.getDSSIdAsString());
        if (xmlCertificate == null) {
            throw new IllegalStateException(String.format(
                    "XML certificate with Id '%s' is not yet created!", certToken.getDSSIdAsString()));
        }

        CertificateWrapper certificateWrapper = new CertificateWrapper(xmlCertificate);
        boolean qcCompliance = certificateWrapper.isQcCompliance();
        List<QCType> qcTypes = certificateWrapper.getQcTypes();
        for (ServiceTypeASi serviceTypeASi : typeAsiEquivalenceMap.values()) {
            if (serviceTypeASi.getAsi() == null) {
                // no aSI -> accept all
                return true;
            }

            if (Utils.isCollectionNotEmpty(qcTypes)) {
                for (QCType qcType : qcTypes) {
                    if (isQcTypeMatch(qcType, serviceTypeASi)) {
                        return true;
                    }
                }

            } else if (qcCompliance) {
                // qcCompliance + no type -> foreSign
                if (isQcTypeMatch(QCTypeEnum.QCT_ESIGN, serviceTypeASi)) {
                    return true;
                }

            } else {
                // no qcType -> accept all
                return true;
            }
        }
        return false;
    }
    
    private boolean isQcTypeMatch(QCType qcType, ServiceTypeASi serviceTypeASi) {
        String asi = serviceTypeASi.getAsi();
        if (QCTypeEnum.QCT_ESIGN.equals(qcType)) {
            return AdditionalServiceInformation.isForeSignatures(asi);
        } else if (QCTypeEnum.QCT_ESEAL.equals(qcType)) {
            return AdditionalServiceInformation.isForeSeals(asi);
        } else if (QCTypeEnum.QCT_WEB.equals(qcType)) {
            return AdditionalServiceInformation.isForWebAuth(asi);
        }
        return false;
    }

    private boolean checkStatusEquivalence(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                           Map<List<String>, List<String>> statusEquivalenceMap) {
        for (Map.Entry<List<String>, List<String>> statusEquivalence : statusEquivalenceMap.entrySet()) {
            if (statusEquivalence.getKey().contains(serviceInfoStatus.getStatus())) {
                return true;
            }
        }
        return false;
    }

    private XmlMRATrustServiceMapping getXmlMRATrustServiceMapping(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                                   CertificateToken certToken, ServiceEquivalence serviceEquivalence) {
        XmlMRATrustServiceMapping mraTrustServiceMapping = new XmlMRATrustServiceMapping();
        mraTrustServiceMapping.setTrustServiceLegalIdentifier(serviceEquivalence.getLegalInfoIdentifier());
        mraTrustServiceMapping.setEquivalenceStatusStartingTime(serviceEquivalence.getStartDate());
        mraTrustServiceMapping.setEquivalenceStatusEndingTime(serviceEquivalence.getEndDate());
        mraTrustServiceMapping.setOriginalThirdCountryMapping(getXmlOriginalThirdCountryTrustServiceMapping(serviceInfoStatus, certToken));
        return mraTrustServiceMapping;
    }

    private XmlOriginalThirdCountryTrustServiceMapping getXmlOriginalThirdCountryTrustServiceMapping(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus, CertificateToken certToken) {
        XmlOriginalThirdCountryTrustServiceMapping originalThirdCountryMapping = new XmlOriginalThirdCountryTrustServiceMapping();
        originalThirdCountryMapping.setServiceType(serviceInfoStatus.getType());
        originalThirdCountryMapping.setStatus(serviceInfoStatus.getStatus());

        List<XmlQualifier> qualifiers = getQualifiers(serviceInfoStatus, certToken);
        if (Utils.isCollectionNotEmpty(qualifiers)) {
            originalThirdCountryMapping.setCapturedQualifiers(qualifiers);
        }

        List<String> additionalServiceInfoUris = serviceInfoStatus.getAdditionalServiceInfoUris();
        if (Utils.isCollectionNotEmpty(additionalServiceInfoUris)) {
            originalThirdCountryMapping.setAdditionalServiceInfoUris(additionalServiceInfoUris);
        }

        return originalThirdCountryMapping;
    }

    private void translateCertificate(CertificateToken certToken, List<ServiceEquivalence> serviceEquivalenceList) {
        // See PRO-4.3.4-03B (apply first enacted serviceEquivalence. NOTE: list inverted)
        XmlQcStatements qcStatements = null;
        for (ServiceEquivalence serviceEquivalence : serviceEquivalenceList) {
            if (serviceEquivalence.getStatus().isEnacted() && check(certToken, serviceEquivalence)) {
                XmlQcStatements currentQcStatement = applyCertContentEquivalence(certToken, serviceEquivalence);
                if (qcStatements == null) {
                    qcStatements = currentQcStatement;

                } else if (!checkQcStatementsEquivalence(qcStatements, currentQcStatement)) {
                    LOG.warn("Enacted MRA equivalences with legal identifier '{}' lead to different certificate " +
                            "content results for a certificate with id '{}'! The equivalence is not applied.",
                            serviceEquivalence.getLegalInfoIdentifier(), certToken.getDSSIdAsString());
                    return;
                }

            } else {
                LOG.debug("MRA equivalence was not applied for a certificate with Id '{}' : '{}'",
                        certToken.getDSSIdAsString(), serviceEquivalence.getLegalInfoIdentifier());
            }
        }

        if (qcStatements != null) {
            LOG.info("MRA equivalence is applied for a certificate with Id '{}' : '{}'",
                    certToken.getDSSIdAsString(), serviceEquivalenceList.iterator().next().getLegalInfoIdentifier());

            // update QcStatements certificate content
            XmlCertificate xmlCertificate = xmlCertsMap.get(certToken.getDSSIdAsString());
            setQcStatements(xmlCertificate, qcStatements);
        }
    }

    private boolean check(CertificateToken certificateToken, ServiceEquivalence serviceEquivalence) {
        // check if a certificate has been issued at or after the starting time of the service equivalence
        Date certIssuance = certificateToken.getNotBefore();
        if (certIssuance.before(serviceEquivalence.getStartDate())) {
            return false;
        }
        if (serviceEquivalence.getEndDate() != null && certIssuance.after(serviceEquivalence.getEndDate())) {
            return false;
        }
        if (!checkCertTypeAsiEquivalence(certificateToken, serviceEquivalence.getTypeAsiEquivalence())) {
            return false;
        }
        return true;
    }

    private TrustServiceStatusAndInformationExtensions getEquivalent(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus,
            ServiceEquivalence serviceEquivalence) {

        ServiceTypeASi typeASiSubstitution = getTypeASiSubstitution(serviceInfoStatus, serviceEquivalence);
        String status = getStatusSubstitution(serviceInfoStatus, serviceEquivalence);
        List<ConditionForQualifiers> qualifiersSubstitution = getQualifiersSubstitution(serviceInfoStatus, serviceEquivalence);

        TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder builder =
                new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder();
        if (typeASiSubstitution != null) {
            builder.setType(typeASiSubstitution.getType());
            if (typeASiSubstitution.getAsi() != null) {
                builder.setAdditionalServiceInfoUris(Collections.singletonList(typeASiSubstitution.getAsi()));
            }
        }
        builder.setStatus(status);
        builder.setConditionsForQualifiers(qualifiersSubstitution);
        // copy
        builder.setStartDate(serviceInfoStatus.getStartDate());
        builder.setEndDate(serviceInfoStatus.getEndDate());
        builder.setNames(serviceInfoStatus.getNames());
        builder.setExpiredCertsRevocationInfo(serviceInfoStatus.getExpiredCertsRevocationInfo());
        builder.setServiceSupplyPoints(serviceInfoStatus.getServiceSupplyPoints());
        return new TrustServiceStatusAndInformationExtensions(builder);
    }

    private ServiceTypeASi getTypeASiSubstitution(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus,
            ServiceEquivalence serviceEquivalence) {
        for (Map.Entry<ServiceTypeASi, ServiceTypeASi> expectedSubstitution : serviceEquivalence.getTypeAsiEquivalence()
                .entrySet()) {
            ServiceTypeASi expected = expectedSubstitution.getKey();
            if (checkServiceTypeASi(serviceInfoStatus, expected)) {
                return substituteTypeASi(serviceInfoStatus, expected, expectedSubstitution.getValue());
            }
        }
        return null;
    }

    private ServiceTypeASi substituteTypeASi(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                             ServiceTypeASi pointed, ServiceTypeASi pointing) {
        ServiceTypeASi serviceTypeASi = new ServiceTypeASi();
        serviceTypeASi.setType(pointing.getType());

        String asiResult;
        if (Utils.isCollectionNotEmpty(serviceInfoStatus.getAdditionalServiceInfoUris())) {
            asiResult = serviceInfoStatus.getAdditionalServiceInfoUris().iterator().next();
            if (asiResult.equals(pointed.getAsi())) {
                asiResult = pointing.getAsi();
            }

        } else {
            asiResult = pointing.getAsi();
        }
        serviceTypeASi.setAsi(asiResult);

        return serviceTypeASi;
    }

    private String getStatusSubstitution(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                         ServiceEquivalence serviceEquivalence) {
        Map<List<String>, List<String>> statusEquivalence = serviceEquivalence.getStatusEquivalence();
        for (Map.Entry<List<String>, List<String>> equivalence : statusEquivalence.entrySet()) {
            List<String> expected = equivalence.getKey();
            if (expected.contains(serviceInfoStatus.getStatus())) {
                return equivalence.getValue().iterator().next();
            }

        }
        return null;
    }

    private List<ConditionForQualifiers> getQualifiersSubstitution(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus, ServiceEquivalence serviceEquivalence) {
        List<ConditionForQualifiers> result = new ArrayList<>();
        Map<String, String> qualifierEquivalence = serviceEquivalence.getQualifierEquivalence();
        for (ConditionForQualifiers qualifierCondition : serviceInfoStatus.getConditionsForQualifiers()) {
            List<String> qualifiers = new ArrayList<>();
            for (String qualifier : qualifierCondition.getQualifiers()) {
                String pointingQualifier = qualifierEquivalence.get(qualifier);
                if (Utils.isStringNotEmpty(pointingQualifier)) {
                    qualifier = pointingQualifier;
                }
                qualifiers.add(qualifier);
            }
            result.add(new ConditionForQualifiers(qualifierCondition.getCondition(), qualifiers, qualifierCondition.isCritical()));
        }
        return result;
    }

    private XmlQcStatements applyCertContentEquivalence(CertificateToken certToken, ServiceEquivalence serviceEquivalence) {
        List<CertificateContentEquivalence> certificateContentEquivalences = serviceEquivalence.getCertificateContentEquivalences();
        if (Utils.isCollectionEmpty(certificateContentEquivalences)) {
            LOG.debug("No MRA equivalence is defined for certificate content.");
            return null;
        }
        assertCertificateContentEquivalenceListIsConsistent(certificateContentEquivalences);

        XmlCertificate xmlCertificate = xmlCertsMap.get(certToken.getDSSIdAsString());
        if (xmlCertificate == null) {
            throw new IllegalStateException(String.format(
                    "XmlCertificate with Id '%s' is not yet created!", certToken.getDSSIdAsString()));
        }

        // Overwrite with information from MRA
        XmlQcStatements qcStatements = getQcStatements(xmlCertificate);
        qcStatements.setEnactedMRA(true);

        XmlMRACertificateMapping xmlMRACertificateMapping = getXmlMRACertificateMapping(qcStatements, serviceEquivalence);
        qcStatements.setMRACertificateMapping(xmlMRACertificateMapping);

        XmlTrustServiceEquivalenceInformation trustServiceEquivalenceInformation = xmlMRACertificateMapping.getTrustServiceEquivalenceInformation();

        for (CertificateContentEquivalence certificateContentEquivalence : certificateContentEquivalences) {
            final MRAEquivalenceContext equivalenceContext = certificateContentEquivalence.getContext();

            if (equivalenceContext != null) {
                final XmlCertificateContentEquivalence xmlCertificateContentEquivalence = new XmlCertificateContentEquivalence();
                xmlCertificateContentEquivalence.setUri(equivalenceContext.getUri());

                final Condition condition = certificateContentEquivalence.getCondition();
                if (condition.check(certToken)) {
                    LOG.info("MRA condition match ({})", equivalenceContext);

                    final QCStatementOids contentReplacement = certificateContentEquivalence.getContentReplacement();
                    switch (equivalenceContext) {
                        case QC_COMPLIANCE:
                            replaceCompliance(qcStatements, contentReplacement);
                            xmlCertificateContentEquivalence.setEnacted(true);
                            break;
                        case QC_TYPE:
                            replaceType(qcStatements, contentReplacement);
                            xmlCertificateContentEquivalence.setEnacted(true);
                            break;
                        case QC_QSCD:
                            replaceQSCD(qcStatements, contentReplacement);
                            xmlCertificateContentEquivalence.setEnacted(true);
                            break;
                        default:
                            LOG.warn("Unsupported equivalence context {}", equivalenceContext);
                            break;
                    }
                }

                trustServiceEquivalenceInformation.getCertificateContentEquivalenceList().add(xmlCertificateContentEquivalence);
            }
        }

        return qcStatements;
    }

    private void assertCertificateContentEquivalenceListIsConsistent(List<CertificateContentEquivalence> certificateContentEquivalences) {
        Set<MRAEquivalenceContext> processedValues = new HashSet<>();
        for (CertificateContentEquivalence certificateContentEquivalence : certificateContentEquivalences) {
            MRAEquivalenceContext context = certificateContentEquivalence.getContext();
            if (processedValues.contains(context)) {
                LOG.warn("The MRA certificate content reference equivalence contains more than one element " +
                        "with '{}' context!", context.getUri());
            }
            processedValues.add(context);
        }
    }

    /**
     * This method returns a deep copy of {@code XmlCertificate}'s {@code XmlQcStatements} extension, when present.
     * Empty object otherwise.
     *
     * @param xmlCertificate {@link XmlCertificate}
     * @return {@link XmlQcStatements}
     */
    private XmlQcStatements getQcStatements(XmlCertificate xmlCertificate) {
        for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
                return qcStatementsBuilder.copy((XmlQcStatements) certificateExtension);
            }
        }
        return new XmlQcStatements();
    }

    /**
     * This method sets new {@code XmlQcStatements} certificate extension to the given {@code XmlCertificate}.
     * The method replaces {@code XmlQcStatements} certificate extension, when present.
     *
     * @param xmlCertificate {@link XmlCertificate}
     * @param xmlQcStatements {@link XmlQcStatements}
     */
    private void setQcStatements(XmlCertificate xmlCertificate, XmlQcStatements xmlQcStatements) {
        Iterator<XmlCertificateExtension> it = xmlCertificate.getCertificateExtensions().iterator();
        while (it.hasNext()) {
            XmlCertificateExtension certificateExtension = it.next();
            if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
                it.remove();
                break;
            }
        }
        xmlCertificate.getCertificateExtensions().add(xmlQcStatements);
    }

    private boolean checkQcStatementsEquivalence(XmlQcStatements qcStatementsOne, XmlQcStatements qcStatementsTwo) {
        if (qcStatementsOne == null && qcStatementsTwo == null) {
            return true;
        } else if (qcStatementsOne == null || qcStatementsTwo == null) {
            return false;
        }

        if (Utils.isTrue(qcStatementsOne.isEnactedMRA()) != Utils.isTrue(qcStatementsTwo.isEnactedMRA())) {
            return false;
        }
        if ((qcStatementsOne.getQcCompliance() != null && qcStatementsOne.getQcCompliance().isPresent()) !=
                (qcStatementsTwo.getQcCompliance() != null && qcStatementsTwo.getQcCompliance().isPresent())) {
            return false;
        }
        if (!qcStatementsOne.getQcTypes().stream().map(XmlOID::getValue).collect(Collectors.toSet()).equals(
                qcStatementsTwo.getQcTypes().stream().map(XmlOID::getValue).collect(Collectors.toSet()))) {
            return false;
        }
        if ((qcStatementsOne.getQcSSCD() != null && qcStatementsOne.getQcSSCD().isPresent()) !=
                (qcStatementsTwo.getQcSSCD() != null && qcStatementsTwo.getQcSSCD().isPresent())) {
            return false;
        }
        return true;
    }

    private XmlMRACertificateMapping getXmlMRACertificateMapping(XmlQcStatements qcStatements,
                                                                 ServiceEquivalence serviceEquivalence) {
        final XmlMRACertificateMapping xmlMRACertificateMapping = new XmlMRACertificateMapping();
        xmlMRACertificateMapping.setTrustServiceEquivalenceInformation(getXmlTrustServiceEquivalenceInformation(serviceEquivalence));
        xmlMRACertificateMapping.setOriginalThirdCountryMapping(getXmlOriginalThirdCountryQcStatementsMapping(qcStatements));
        return xmlMRACertificateMapping;
    }

    private XmlTrustServiceEquivalenceInformation getXmlTrustServiceEquivalenceInformation(ServiceEquivalence serviceEquivalence) {
        final XmlTrustServiceEquivalenceInformation xmlTrustServiceEquivalenceInformation = new XmlTrustServiceEquivalenceInformation();
        xmlTrustServiceEquivalenceInformation.setTrustServiceLegalIdentifier(serviceEquivalence.getLegalInfoIdentifier());
        return xmlTrustServiceEquivalenceInformation;
    }

    private XmlOriginalThirdCountryQcStatementsMapping getXmlOriginalThirdCountryQcStatementsMapping(XmlQcStatements qcStatements) {
        final XmlOriginalThirdCountryQcStatementsMapping originalQcStatements = new XmlOriginalThirdCountryQcStatementsMapping();
        if (qcStatements.getQcCompliance() != null) {
            originalQcStatements.setQcCompliance(qcStatementsBuilder.buildXmlQcCompliance(qcStatements.getQcCompliance().isPresent()));
        }
        if (qcStatements.getQcSSCD() != null) {
            originalQcStatements.setQcSSCD(qcStatementsBuilder.buildXmlQcSSCD(qcStatements.getQcSSCD().isPresent()));
        }
        List<XmlOID> originalQcTypes = qcStatements.getQcTypes();
        if (Utils.isCollectionNotEmpty(originalQcTypes)) {
            originalQcStatements.setQcTypes(new ArrayList<>(originalQcTypes));
        }
        List<String> qcCClegislations = qcStatements.getQcCClegislation();
        if (Utils.isCollectionNotEmpty(qcCClegislations)) {
            originalQcStatements.setQcCClegislation(new ArrayList<>(qcCClegislations));
        }
        List<XmlOID> otherOIDs = qcStatements.getOtherOIDs();
        if (Utils.isCollectionNotEmpty(otherOIDs)) {
            originalQcStatements.setOtherOIDs(new ArrayList<>(otherOIDs));
        }
        return originalQcStatements;
    }

    private void replaceCompliance(XmlQcStatements qcStatements,
                                   QCStatementOids contentReplacement) {
        boolean isQcCompliance = false;
        List<String> qcCClegislations = qcStatements.getQcCClegislation();
        for (String oid : contentReplacement.getQcStatementIds()) {
            if (QcStatementUtils.isQcCompliance(oid)) {
                isQcCompliance = true;
            }
        }
        if (Utils.isCollectionNotEmpty(contentReplacement.getQcCClegislations())) {
            qcCClegislations = contentReplacement.getQcCClegislations();
        }
        for (String oid : contentReplacement.getQcStatementIdsToRemove()) {
            if (QcStatementUtils.isQcCompliance(oid)) {
                isQcCompliance = false;
            }
            if (QcStatementUtils.isQcCClegislation(oid)) {
                if (Utils.isCollectionNotEmpty(contentReplacement.getQcCClegislationsToRemove())) {
                    qcCClegislations.removeAll(contentReplacement.getQcCClegislationsToRemove());
                } else {
                    qcCClegislations.clear();
                }
            }
        }
        qcStatements.setQcCompliance(qcStatementsBuilder.buildXmlQcCompliance(isQcCompliance));
        qcStatements.setQcCClegislation(qcCClegislations);
    }

    private void replaceType(XmlQcStatements qcStatements,
                             QCStatementOids contentReplacement) {
        List<XmlOID> originalQcTypes = qcStatements.getQcTypes();
        List<String> qcTypesIds = originalQcTypes.stream().map(XmlOID::getValue).collect(Collectors.toList());
        if (Utils.isCollectionNotEmpty(contentReplacement.getQcTypeIds())) {
            qcTypesIds = contentReplacement.getQcTypeIds();
        }
        for (String oid : contentReplacement.getQcStatementIdsToRemove()) {
            if (QcStatementUtils.isQcType(oid)) {
                if (Utils.isCollectionNotEmpty(contentReplacement.getQcTypeIdsToRemove())) {
                    qcTypesIds.removeAll(contentReplacement.getQcTypeIdsToRemove());
                } else {
                    qcTypesIds.clear();
                }
            }
        }
        List<QCType> qcTypes = QcStatementUtils.getQcTypes(qcTypesIds);
        qcStatements.setQcTypes(qcStatementsBuilder.buildXmlQcTypes(qcTypes));
    }

    private void replaceQSCD(XmlQcStatements qcStatements,
                             QCStatementOids contentReplacement) {
        boolean isQcSSCD = false;
        for (String oid : contentReplacement.getQcStatementIds()) {
            if (QcStatementUtils.isQcSSCD(oid)) {
                isQcSSCD = true;
            }
        }
        for (String oid : contentReplacement.getQcStatementIdsToRemove()) {
            if (QcStatementUtils.isQcSSCD(oid)) {
                isQcSSCD = false;
            }
        }
        qcStatements.setQcSSCD(qcStatementsBuilder.buildXmlQcSSCD(isQcSSCD));
    }

}
