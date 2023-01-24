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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRACertificateMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRATrustServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryQcStatementsMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryTrustedServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedServiceProvider;
import eu.europa.esig.dss.enumerations.AdditionalServiceInformation;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.enumerations.MRAStatus;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.QcStatementUtils;
import eu.europa.esig.dss.spi.tsl.CertificateContentEquivalence;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.spi.tsl.MRA;
import eu.europa.esig.dss.spi.tsl.QCStatementOids;
import eu.europa.esig.dss.spi.tsl.ServiceEquivalence;
import eu.europa.esig.dss.spi.tsl.ServiceTypeASi;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * This class is used to build a {@code XmlTrustedServiceProvider} object instance
 *
 */
public class XmlTrustedServiceProviderBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(XmlTrustedServiceProviderBuilder.class);

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
    public XmlTrustedServiceProviderBuilder(final Map<String, XmlCertificate> xmlCertsMap,
                                            final Map<String, XmlTrustedList> xmlTrustedListsMap,
                                            final Map<String, TLInfo> tlInfoMap) {
        this.xmlCertsMap = xmlCertsMap;
        this.xmlTrustedListsMap = xmlTrustedListsMap;
        this.tlInfoMap = tlInfoMap;
    }

    /**
     * This method builds a list of {@link XmlTrustedServiceProvider}s corresponding to the given {@code CertificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get a list of {@link XmlTrustedServiceProvider}s
     * @param relatedTrustServices a map of trust anchor {@link CertificateToken}s and their corresponding trusted services
     * @return a list of {@link XmlTrustedServiceProvider}s
     */
    public List<XmlTrustedServiceProvider> build(CertificateToken certificateToken,
                                                 Map<CertificateToken, List<TrustProperties>> relatedTrustServices) {
        List<XmlTrustedServiceProvider> result = new ArrayList<>();
        for (Map.Entry<CertificateToken, List<TrustProperties>> entry : relatedTrustServices.entrySet()) {
            CertificateToken trustedCert = entry.getKey();
            List<TrustProperties> services = entry.getValue();

            Map<TrustServiceProvider, List<TrustProperties>> servicesByProviders = classifyByServiceProvider(services);

            for (Map.Entry<TrustServiceProvider, List<TrustProperties>> servicesByProvider : servicesByProviders
                    .entrySet()) {

                List<TrustProperties> trustServices = servicesByProvider.getValue();
                if (Utils.isCollectionNotEmpty(trustServices)) {
                    result.add(getXmlTrustedServiceProvider(certificateToken, trustServices, trustedCert));
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

    private XmlTrustedServiceProvider getXmlTrustedServiceProvider(CertificateToken certificateToken, List<TrustProperties> trustServices,
                                                                   CertificateToken trustAnchor) {
        TrustProperties trustProperties = trustServices.iterator().next();

        XmlTrustedServiceProvider result = new XmlTrustedServiceProvider();
        if (trustProperties.getLOTLIdentifier() != null) {
            result.setLOTL(xmlTrustedListsMap.get(trustProperties.getLOTLIdentifier().asXmlId()));
        }
        if (trustProperties.getTLIdentifier() != null) {
            result.setTL(xmlTrustedListsMap.get(trustProperties.getTLIdentifier().asXmlId()));
        }
        TrustServiceProvider tsp = trustProperties.getTrustServiceProvider();
        result.setTSPNames(getLangAndValues(tsp.getNames()));
        result.setTSPTradeNames(getLangAndValues(tsp.getTradeNames()));
        result.setTSPRegistrationIdentifiers(tsp.getRegistrationIdentifiers());

        result.setTrustedServices(buildXmlTrustedServicesList(certificateToken, trustServices, trustAnchor));

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

    private List<XmlTrustedService> buildXmlTrustedServicesList(CertificateToken certToken, List<TrustProperties> trustServices,
                                                                CertificateToken trustAnchor) {
        List<XmlTrustedService> result = new ArrayList<>();

        for (TrustProperties trustProperties : trustServices) {
            TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService =
                    trustProperties.getTrustService();
            List<TrustServiceStatusAndInformationExtensions> serviceStatusAfterOfEqualsCertIssuance =
                    trustService.getAfter(certToken.getNotBefore());
            if (Utils.isCollectionNotEmpty(serviceStatusAfterOfEqualsCertIssuance)) {
                for (TrustServiceStatusAndInformationExtensions serviceInfoStatus : serviceStatusAfterOfEqualsCertIssuance) {
                    MRA mra = getMRA(trustProperties);
                    if (mra != null) {
                        result.addAll(buildXmlTrustedServicesWithMRA(serviceInfoStatus, certToken, trustAnchor, mra));
                    } else {
                        result.add(getXmlTrustedService(serviceInfoStatus, certToken, trustAnchor));
                    }
                }
            }
        }
        return Collections.unmodifiableList(result);
    }

    private MRA getMRA(TrustProperties trustProperties) {
        if (trustProperties.getTLIdentifier() != null) {
            TLInfo tlInfo = tlInfoMap.get(trustProperties.getTLIdentifier().asXmlId());
            if (tlInfo != null) {
                // may be null when no TLValidationJob is used
                return tlInfo.getMra();
            }
        }
        return null;
    }

    private XmlTrustedService getXmlTrustedService(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                   CertificateToken certToken, CertificateToken trustAnchor) {
        XmlTrustedService trustedService = new XmlTrustedService();

        trustedService.setServiceDigitalIdentifier(xmlCertsMap.get(trustAnchor.getDSSIdAsString()));
        trustedService.setServiceNames(getLangAndValues(serviceInfoStatus.getNames()));
        trustedService.setServiceType(serviceInfoStatus.getType());
        trustedService.setStatus(serviceInfoStatus.getStatus());
        trustedService.setStartDate(serviceInfoStatus.getStartDate());
        trustedService.setEndDate(serviceInfoStatus.getEndDate());

        List<String> qualifiers = getQualifiers(serviceInfoStatus, certToken);
        if (Utils.isCollectionNotEmpty(qualifiers)) {
            trustedService.setCapturedQualifiers(qualifiers);
        }

        List<String> additionalServiceInfoUris = serviceInfoStatus.getAdditionalServiceInfoUris();
        if (Utils.isCollectionNotEmpty(additionalServiceInfoUris)) {
            trustedService.setAdditionalServiceInfoUris(additionalServiceInfoUris);
        }

        List<String> serviceSupplyPoints = serviceInfoStatus.getServiceSupplyPoints();
        if (Utils.isCollectionNotEmpty(serviceSupplyPoints)) {
            trustedService.setServiceSupplyPoints(serviceSupplyPoints);
        }

        trustedService.setExpiredCertsRevocationInfo(serviceInfoStatus.getExpiredCertsRevocationInfo());

        return trustedService;
    }

    /**
     * Retrieves all the qualifiers for which the corresponding conditionEntry is true.
     *
     * @param serviceInfoStatus {@link TrustServiceStatusAndInformationExtensions}
     * @param certificateToken {@link CertificateToken}
     * @return a list of {@link String} qualifiers
     */
    private List<String> getQualifiers(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                       CertificateToken certificateToken) {
        LOG.trace("--> GET_QUALIFIERS()");
        List<String> list = new ArrayList<>();
        final List<ConditionForQualifiers> conditionsForQualifiers = serviceInfoStatus.getConditionsForQualifiers();
        if (Utils.isCollectionNotEmpty(conditionsForQualifiers)) {
            for (ConditionForQualifiers conditionForQualifiers : conditionsForQualifiers) {
                Condition condition = conditionForQualifiers.getCondition();
                if (condition.check(certificateToken)) {
                    list.addAll(conditionForQualifiers.getQualifiers());
                }
            }
        }
        return list;
    }

    private List<XmlTrustedService> buildXmlTrustedServicesWithMRA(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus, CertificateToken certToken,
            CertificateToken trustAnchor, MRA mra) {
        if (Utils.isCollectionNotEmpty(serviceInfoStatus.getAdditionalServiceInfoUris())) {
            List<XmlTrustedService> result = new ArrayList<>();
            for (String aSI : serviceInfoStatus.getAdditionalServiceInfoUris()) {
                TrustServiceStatusAndInformationExtensions serviceInfoStatusCopy =
                        new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder(serviceInfoStatus)
                                .setAdditionalServiceInfoUris(Collections.singletonList(aSI)).build();
                result.add(getXmlTrustedServiceForMRA(serviceInfoStatusCopy, certToken, trustAnchor, mra));
            }
            return result;

        } else {
            return Collections.singletonList(getXmlTrustedServiceForMRA(serviceInfoStatus, certToken, trustAnchor, mra));
        }
    }

    private XmlTrustedService getXmlTrustedServiceForMRA(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                         CertificateToken certToken, CertificateToken trustAnchor, MRA mra) {
        XmlMRATrustServiceMapping xmlMRATrustServiceMapping = null;
        List<ServiceEquivalence> mraEquivalences = getMRAServiceEquivalences(serviceInfoStatus, mra);
        boolean enactedMra = Utils.isCollectionNotEmpty(mraEquivalences);
        if (enactedMra) {
            if (mraEquivalences.size() == 1) {
                ServiceEquivalence serviceEquivalence = mraEquivalences.iterator().next();
                LOG.info("MRA equivalence is applied for a Trusted Service : '{}'",
                        serviceEquivalence.getLegalInfoIdentifier());

                // shall be computed before translation
                xmlMRATrustServiceMapping = getXmlMRATrustServiceMapping(serviceInfoStatus, serviceEquivalence, certToken);
                serviceInfoStatus = translate(serviceInfoStatus, certToken, serviceEquivalence);

            } else {
                LOG.warn("More than one MRA equivalence found for a Trusted Service!");
            }
        }

        XmlTrustedService xmlTrustedService = getXmlTrustedService(serviceInfoStatus, certToken, trustAnchor);
        xmlTrustedService.setMRATrustServiceMapping(xmlMRATrustServiceMapping);
        if (xmlMRATrustServiceMapping != null) {
            xmlTrustedService.setEnactedMRA(true);
        }
        return xmlTrustedService;
    }

    private List<ServiceEquivalence> getMRAServiceEquivalences(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
                                                               MRA mra) {
        LOG.debug("MRA");
        final List<ServiceEquivalence> equivalences = new ArrayList<>();
        for (ServiceEquivalence serviceEquivalence : mra.getServiceEquivalence()) {
            if (MRAStatus.ENACTED == serviceEquivalence.getStatus()
                    && check(serviceInfoStatus, serviceEquivalence)) {
                equivalences.add(serviceEquivalence);
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
                                                                   ServiceEquivalence serviceEquivalence, CertificateToken certToken) {
        XmlMRATrustServiceMapping mraTrustServiceMapping = new XmlMRATrustServiceMapping();
        mraTrustServiceMapping.setTrustServiceLegalIdentifier(serviceEquivalence.getLegalInfoIdentifier());
        mraTrustServiceMapping.setEquivalenceStatusStartingTime(serviceEquivalence.getStartDate());
        mraTrustServiceMapping.setOriginalThirdCountryMapping(getXmlOriginalThirdCountryTrustedServiceMapping(serviceInfoStatus, certToken));
        return mraTrustServiceMapping;
    }

    private XmlOriginalThirdCountryTrustedServiceMapping getXmlOriginalThirdCountryTrustedServiceMapping(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus, CertificateToken certToken) {
        XmlOriginalThirdCountryTrustedServiceMapping originalThirdCountryMapping = new XmlOriginalThirdCountryTrustedServiceMapping();
        originalThirdCountryMapping.setServiceType(serviceInfoStatus.getType());
        originalThirdCountryMapping.setStatus(serviceInfoStatus.getStatus());

        List<String> qualifiers = getQualifiers(serviceInfoStatus, certToken);
        if (Utils.isCollectionNotEmpty(qualifiers)) {
            originalThirdCountryMapping.setCapturedQualifiers(qualifiers);
        }

        List<String> additionalServiceInfoUris = serviceInfoStatus.getAdditionalServiceInfoUris();
        if (Utils.isCollectionNotEmpty(additionalServiceInfoUris)) {
            originalThirdCountryMapping.setAdditionalServiceInfoUris(additionalServiceInfoUris);
        }

        return originalThirdCountryMapping;
    }

    private TrustServiceStatusAndInformationExtensions translate(
            TrustServiceStatusAndInformationExtensions serviceInfoStatus, CertificateToken certToken,
            ServiceEquivalence serviceEquivalence) {
        TrustServiceStatusAndInformationExtensions equivalent = getEquivalent(serviceInfoStatus, serviceEquivalence);

        if (check(certToken, serviceEquivalence)) {
            LOG.info("MRA equivalence is applied for a certificate with Id '{}' : '{}'",
                    certToken.getDSSIdAsString(), serviceEquivalence.getLegalInfoIdentifier());
            overrideCertContent(certToken, serviceEquivalence);

        } else {
            LOG.debug("MRA equivalence was not applied for a certificate with Id '{}' : '{}'",
                    certToken.getDSSIdAsString(), serviceEquivalence.getLegalInfoIdentifier());
        }

        return equivalent;
    }

    private boolean check(CertificateToken certificateToken, ServiceEquivalence serviceEquivalence) {
        // check if a certificate has been issued at or after the starting time of the service equivalence
        Date certIssuance = certificateToken.getNotBefore();
        if (certIssuance.before(serviceEquivalence.getStartDate())) {
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
            result.add(new ConditionForQualifiers(qualifierCondition.getCondition(), qualifiers));
        }
        return result;
    }

    private void overrideCertContent(CertificateToken certToken, ServiceEquivalence serviceEquivalence) {
        Map<MRAEquivalenceContext, CertificateContentEquivalence> certificateContentEquivalences = serviceEquivalence.getCertificateContentEquivalences();
        if (Utils.isMapEmpty(certificateContentEquivalences)) {
            LOG.debug("No MRA equivalence is defined for certificate content.");
            return;
        }

        XmlCertificate xmlCertificate = xmlCertsMap.get(certToken.getDSSIdAsString());
        if (xmlCertificate == null) {
            throw new IllegalStateException(String.format(
                    "XmlCertificate with Id '%s' is not yet created!", certToken.getDSSIdAsString()));
        }

        // Overwrite with information from MRA
        XmlQcStatements qcStatements = null;
        for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
                qcStatements = (XmlQcStatements) certificateExtension;
            }
        }
        if (qcStatements == null) {
            qcStatements = new XmlQcStatements();
            xmlCertificate.getCertificateExtensions().add(qcStatements);
        }

        for (Map.Entry<MRAEquivalenceContext, CertificateContentEquivalence> equivalence : certificateContentEquivalences.entrySet()) {
            MRAEquivalenceContext equivalenceContext = equivalence.getKey();
            CertificateContentEquivalence certificateContentEquivalence = equivalence.getValue();

            Condition condition = certificateContentEquivalence.getCondition();
            if (condition.check(certToken)) {
                LOG.info("MRA condition match ({})", equivalenceContext);
                if (qcStatements.getMRACertificateMapping() == null) {
                    qcStatements.setMRACertificateMapping(getXmlMRACertificateMapping(qcStatements, serviceEquivalence));
                    qcStatements.setEnactedMRA(true);
                }

                QCStatementOids contentReplacement = certificateContentEquivalence.getContentReplacement();
                switch (equivalenceContext) {
                    case QC_COMPLIANCE:
                        replaceCompliance(qcStatements, contentReplacement);
                        break;
                    case QC_TYPE:
                        replaceType(qcStatements, contentReplacement);
                        break;
                    case QC_QSCD:
                        replaceQSCD(qcStatements, contentReplacement);
                        break;
                    default:
                        LOG.warn("Unsupported equivalence context {}", equivalence.getKey());
                        break;
                }
            }
        }
    }

    private XmlMRACertificateMapping getXmlMRACertificateMapping(XmlQcStatements qcStatements,
                                                                 ServiceEquivalence serviceEquivalence) {
        XmlMRACertificateMapping xmlMRACertificateMapping = new XmlMRACertificateMapping();
        xmlMRACertificateMapping.setEnactedTrustServiceLegalIdentifier(serviceEquivalence.getLegalInfoIdentifier());
        xmlMRACertificateMapping.setOriginalThirdCountryMapping(getXmlOriginalThirdCountryQcStatementsMapping(qcStatements));
        return xmlMRACertificateMapping;
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
        qcStatements.getQcSSCD().setPresent(isQcSSCD);
    }

}
