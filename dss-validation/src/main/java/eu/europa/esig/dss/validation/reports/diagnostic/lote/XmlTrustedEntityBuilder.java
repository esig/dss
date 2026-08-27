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
package eu.europa.esig.dss.validation.reports.diagnostic.lote;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlListOfTrustedEntities;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedEntity;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedEntityService;
import eu.europa.esig.dss.model.lote.LoLoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.ServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.lote.TrustedEntity;
import eu.europa.esig.dss.model.lote.TrustedProperties;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds a {@code eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedEntity} instance
 *
 */
public class XmlTrustedEntityBuilder {

    /**
     * The map of certificates identifiers and their corresponding XML representations
     */
    private final Map<String, XmlCertificate> xmlCertsMap;

    /**
     * The map of Trust Sources
     */
    private final Map<String, XmlListOfTrustedEntities> xmlTrustSourceListsMap;

    /**
     * Default constructor
     *
     * @param xmlCertsMap a map of certificate identifiers and corresponding XML representations
     * @param xmlTrustSourceListsMap a map of trust source list identifiers and corresponding XML representations
     */
    public XmlTrustedEntityBuilder(final Map<String, XmlCertificate> xmlCertsMap,
                                  final Map<String, XmlListOfTrustedEntities> xmlTrustSourceListsMap) {
        this.xmlCertsMap = xmlCertsMap;
        this.xmlTrustSourceListsMap = xmlTrustSourceListsMap;
    }

    /**
     * This method builds a list of {@link XmlTrustedEntity}s corresponding to the given {@code CertificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get a list of {@link XmlTrustedEntity}s
     * @param relatedTrustedProperties a map of trust anchor {@link CertificateToken}s and their corresponding trusted services
     * @return a list of {@link XmlTrustedEntity}s
     */
    public List<XmlTrustedEntity> build(CertificateToken certificateToken,
                                        Map<CertificateToken, List<TrustedProperties>> relatedTrustedProperties) {
        List<XmlTrustedEntity> result = new ArrayList<>();
        for (Map.Entry<CertificateToken, List<TrustedProperties>> entry : relatedTrustedProperties.entrySet()) {
            CertificateToken trustedCert = entry.getKey();
            List<TrustedProperties> services = entry.getValue();

            Map<TrustedEntity, List<TrustedProperties>> servicesByProviders = classifyByServiceProvider(services);

            for (Map.Entry<TrustedEntity, List<TrustedProperties>> servicesByProvider : servicesByProviders
                    .entrySet()) {

                List<TrustedProperties> trustServices = servicesByProvider.getValue();
                if (Utils.isCollectionNotEmpty(trustServices)) {
                    result.add(getXmlTrustedEntity(certificateToken, trustServices, trustedCert));
                }
            }

        }
        return Collections.unmodifiableList(result);
    }

    private Map<TrustedEntity, List<TrustedProperties>> classifyByServiceProvider(
            List<TrustedProperties> trustPropertiesList) {
        Map<TrustedEntity, List<TrustedProperties>> servicesByProviders = new HashMap<>();
        if (Utils.isCollectionNotEmpty(trustPropertiesList)) {
            for (TrustedProperties trustProperties : trustPropertiesList) {
                TrustedEntity currentTrustedEntity = trustProperties.getTrustedEntity();
                List<TrustedProperties> list = servicesByProviders.computeIfAbsent(currentTrustedEntity, k -> new ArrayList<>());
                list.add(trustProperties);
            }
        }
        return servicesByProviders;
    }

    private XmlTrustedEntity getXmlTrustedEntity(CertificateToken certificateToken, List<TrustedProperties> trustServices,
                                                               CertificateToken trustAnchor) {
        TrustedProperties trustProperties = trustServices.iterator().next();

        final XmlTrustedEntity result = new XmlTrustedEntity();

        LoLoTEInfo loloteInfo = trustProperties.getLoLoTEInfo();
        if (loloteInfo != null) {
            XmlListOfTrustedEntities xmlLoLoTE = xmlTrustSourceListsMap.get(loloteInfo.getDSSIdAsString());
            if (xmlLoLoTE == null) {
                throw new IllegalStateException(String.format("LOTL with Id '%s' has not been found! " +
                        "Please verify TrustedPropertiesCertificateSource contains LoTEValidationSummary.", loloteInfo.getDSSIdAsString()));
            }
            result.setLoLoTE(xmlLoLoTE);
        }
        LoTEInfo loteInfo = trustProperties.getLoTEInfo();
        if (loteInfo != null) {
            XmlListOfTrustedEntities xmlLoTE = xmlTrustSourceListsMap.get(loteInfo.getDSSIdAsString());
            if (xmlLoTE == null) {
                throw new IllegalStateException(String.format("TL with Id '%s' has not been found! " +
                        "Please verify TrustedPropertiesCertificateSource contains LoTEValidationSummary.", loteInfo.getDSSIdAsString()));
            }
            result.setLoTE(xmlLoTE);
        }

        TrustedEntity tsp = trustProperties.getTrustedEntity();
        result.setNames(getLangAndValues(tsp.getNames()));
        result.setTradeNames(getLangAndValues(tsp.getTradeNames()));
        result.setRegistrationIdentifiers(tsp.getRegistrationIdentifiers());

        result.setTrustedEntityServices(buildXmlTrustedEntityServicesList(certificateToken, trustServices, trustAnchor));

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

    private List<XmlTrustedEntityService> buildXmlTrustedEntityServicesList(CertificateToken certToken, List<TrustedProperties> trustServices,
                                                                            CertificateToken trustAnchor) {
        List<XmlTrustedEntityService> result = new ArrayList<>();

        for (TrustedProperties trustProperties : trustServices) {
            TimeDependentValues<ServiceStatusAndInformationExtensions> trustService =
                    trustProperties.getTrustedServices();
            List<ServiceStatusAndInformationExtensions> serviceStatusAfterOfEqualsCertIssuance =
                    trustService.getAfter(certToken.getNotBefore());
            if (Utils.isCollectionNotEmpty(serviceStatusAfterOfEqualsCertIssuance)) {
                for (ServiceStatusAndInformationExtensions serviceInfoStatus : serviceStatusAfterOfEqualsCertIssuance) {
                    result.add(getXmlTrustedEntityService(serviceInfoStatus, trustAnchor));
                }
            }
        }
        return Collections.unmodifiableList(result);
    }

    private XmlTrustedEntityService getXmlTrustedEntityService(ServiceStatusAndInformationExtensions serviceInfoStatus,
                                                               CertificateToken trustAnchor) {
        XmlTrustedEntityService trustService = new XmlTrustedEntityService();

        trustService.setServiceDigitalIdentifier(xmlCertsMap.get(trustAnchor.getDSSIdAsString()));
        trustService.setServiceNames(getLangAndValues(serviceInfoStatus.getNames()));
        trustService.setServiceType(serviceInfoStatus.getType());
        trustService.setStatus(serviceInfoStatus.getStatus());
        trustService.setStartDate(serviceInfoStatus.getStartDate());
        trustService.setEndDate(serviceInfoStatus.getEndDate());

        List<String> serviceSupplyPoints = serviceInfoStatus.getServiceSupplyPoints();
        if (Utils.isCollectionNotEmpty(serviceSupplyPoints)) {
            trustService.setServiceSupplyPoints(serviceSupplyPoints);
        }

        return trustService;
    }
    
}
