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

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateApprovalStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateApprovalStatus;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedEntityServiceWrapper;
import eu.europa.esig.dss.diagnostic.TrustedSourceServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatus;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatusEnum;
import eu.europa.esig.dss.enumerations.ListType;
import eu.europa.esig.dss.enumerations.LoTEServiceStatus;
import eu.europa.esig.dss.enumerations.LoTEServiceTypeIdentifier;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.TrustedEntityServiceAtTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.TrustedEntityServiceStatusConsistencyCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.TrustedEntityServiceStatusKnownCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.TrustedEntityServiceTypeIdentifierKnownCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.checks.TrustedEntityServiceWithStiCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedEntitiesFilterFactory;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedEntityServiceFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Verifies certificate's approval revocation at the given time
 * 
 */
public class CertificateApprovalStatusAtTimeBlock extends Chain<XmlValidationCertificateApprovalStatus> {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateApprovalStatusAtTimeBlock.class);

    /** The time type to get the qualification at */
    private final ValidationTime validationTime;

    /** The time to check against */
    private final Date date;

    /** Corresponding LoTE Type URI */
    private final String listTypeUri;

    /** Service Type Identifier URI */
    private final String stiUri;

    /** List of matching TrustServices */
    private final List<TrustedEntityServiceWrapper> acceptableServices;

    /** Cached list of filtered services */
    private List<TrustedEntityServiceWrapper> filteredServices;

    /**
     * Constructor to instantiate the validation at the certificate's issuance time
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param signingCertificate {@link CertificateWrapper} to get qualification for
     * @param listTypeUri {@link String} representing a type of the List of Trusted Entities to be evaluated
     * @param stiUri {@link String} representing a target service type identifier
     * @param acceptableServices list of {@link TrustedEntityServiceWrapper}s
     */
    public CertificateApprovalStatusAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime,
                                                CertificateWrapper signingCertificate, String listTypeUri, String stiUri, List<TrustedEntityServiceWrapper> acceptableServices) {
        this(i18nProvider, validationTime, null, signingCertificate, listTypeUri, stiUri, acceptableServices);
    }

    /**
     * Constructor to instantiate the validation at the validation time
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param date {@link Date}
     * @param signingCertificate {@link CertificateWrapper} to get qualification for
     * @param listTypeUri {@link String} representing a type of the List of Trusted Entities to be evaluated
     * @param stiUri {@link String} representing a target service type identifier
     * @param acceptableServices list of {@link TrustedEntityServiceWrapper}s
     */
    public CertificateApprovalStatusAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime, Date date,
                                                CertificateWrapper signingCertificate, String listTypeUri, String stiUri, List<TrustedEntityServiceWrapper> acceptableServices) {
        super(i18nProvider, new XmlValidationCertificateApprovalStatus());
        result.setId(signingCertificate.getId());

        this.validationTime = validationTime;
        this.listTypeUri = listTypeUri;
        this.stiUri = stiUri;
        this.acceptableServices = new ArrayList<>(acceptableServices);

        switch (validationTime) {
            case CERTIFICATE_ISSUANCE_TIME:
                this.date = signingCertificate.getNotBefore();
                break;
            case BEST_SIGNATURE_TIME:
            case VALIDATION_TIME:
                this.date = date;
                break;
            default:
                throw new IllegalArgumentException("Unknown qualification time : " + validationTime);
        }
    }

    @Override
    protected String buildChainTitle() {
        MessageTag message = MessageTag.CERT_USAGE_AT_TIME;
        MessageTag param = ValidationProcessUtils.getValidationTimeMessageTag(validationTime);
        return i18nProvider.getMessage(message, getStiUserFriendlyLabel(), param);
    }

    private String getStiUserFriendlyLabel() {
        LoTEServiceTypeIdentifier sti = LoTEServiceTypeIdentifier.fromUri(stiUri);
        if (sti != null && sti.getLabel() != null) {
            return sti.getLabel();
        }
        return stiUri;
    }

    @Override
    protected void initChain() {

        // Init internal variable to the provided list of extracted Trust Services
        filteredServices = new ArrayList<>(acceptableServices);

        // 1b. Filter by date
        TrustedEntityServiceFilter filter = TrustedEntitiesFilterFactory.createFilterByDate(date);
        filteredServices = filter.filter(filteredServices);

        ChainItem<XmlValidationCertificateApprovalStatus> item = firstItem = hasTrustedServiceAtTime(filteredServices);

        // 2a. Check sti consistency

        item = item.setNextItem(trustedServiceTypeIdentifierKnown(stiUri));

        filter = TrustedEntitiesFilterFactory.createFilterByServiceTypeIdentifierUri(stiUri);
        filteredServices = filter.filter(filteredServices);

        item = item.setNextItem(trustedServicesWithSti(filteredServices));

        // 2b. Check revocation consistency
        item = item.setNextItem(trustedServicesStatusConsistent(filteredServices));

        String serviceStatusUri = getServiceStatusUri(filteredServices);
        if (serviceStatusUri != null) {
            item = item.setNextItem(trustedServiceStatusKnown(serviceStatusUri));
        }
        // NOTE: revocation can be null, validate successfully in this case

    }

    @Override
    protected void addAdditionalInfo() {
        XmlCertificateApprovalStatus certificateApprovalStatus = new XmlCertificateApprovalStatus();
        ListType listType = ListType.fromUri(listTypeUri);
        certificateApprovalStatus.setListType(listType);
        String serviceStiUri = getServiceStiUri(filteredServices);
        LoTEServiceTypeIdentifier sti = LoTEServiceTypeIdentifier.fromUri(serviceStiUri);
        certificateApprovalStatus.setServiceTypeIdentifier(sti);
        String serviceStatusUri = getServiceStatusUri(filteredServices);
        LoTEServiceStatus status = LoTEServiceStatus.fromUri(serviceStatusUri);
        certificateApprovalStatus.setServiceStatus(status);

        CertificateApprovalStatus certApprovalStatus = CertificateApprovalStatus.fromDefinition(listType, sti, status);
        if (certApprovalStatus == null) {
            certApprovalStatus = CertificateApprovalStatusEnum.CERT_FOR_UNKNOWN;
        }
        certificateApprovalStatus.setLabel(certApprovalStatus.getLabel());
        result.setCertificateApprovalStatus(certificateApprovalStatus);

        result.setValidationTime(validationTime);
        result.setDateTime(date);
    }

    private ChainItem<XmlValidationCertificateApprovalStatus> hasTrustedServiceAtTime(List<TrustedEntityServiceWrapper> trustedServices) {
        return new TrustedEntityServiceAtTimeCheck(i18nProvider, result, trustedServices, validationTime, getFailLevelRule());
    }

    private ChainItem<XmlValidationCertificateApprovalStatus> trustedServicesWithSti(List<TrustedEntityServiceWrapper> trustedServices) {
        return new TrustedEntityServiceWithStiCheck(i18nProvider, result, trustedServices, stiUri, getFailLevelRule());
    }

    private ChainItem<XmlValidationCertificateApprovalStatus> trustedServiceTypeIdentifierKnown(String serviceStatusUri) {
        return new TrustedEntityServiceTypeIdentifierKnownCheck(i18nProvider, result, serviceStatusUri, getWarnLevelRule());
    }

    private ChainItem<XmlValidationCertificateApprovalStatus> trustedServicesStatusConsistent(List<TrustedEntityServiceWrapper> trustedServices) {
        return new TrustedEntityServiceStatusConsistencyCheck(i18nProvider, result, trustedServices, getFailLevelRule());
    }

    private ChainItem<XmlValidationCertificateApprovalStatus> trustedServiceStatusKnown(String serviceStatusUri) {
        return new TrustedEntityServiceStatusKnownCheck(i18nProvider, result, serviceStatusUri, getWarnLevelRule());
    }

    private String getServiceStiUri(List<TrustedEntityServiceWrapper> filteredServices) {
        Set<String> stiSet = filteredServices.stream().map(TrustedSourceServiceWrapper::getType).collect(Collectors.toSet());
        if (Utils.collectionSize(stiSet) == 0) {
            return null;
        } else if (Utils.collectionSize(stiSet) == 1) {
            return stiSet.iterator().next();
        }
        LOG.warn("Conflict in service type identifier detected!");
        return "?";
    }

    private String getServiceStatusUri(List<TrustedEntityServiceWrapper> filteredServices) {
        Set<String> statusSet = filteredServices.stream().map(TrustedSourceServiceWrapper::getStatus).collect(Collectors.toSet());
        if (Utils.collectionSize(statusSet) == 0) {
            return null;
        } else if (Utils.collectionSize(statusSet) == 1) {
            return statusSet.iterator().next();
        }
        LOG.warn("Conflict in service statuses detected!");
        return "?";
    }
    
}
