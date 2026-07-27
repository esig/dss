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
package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.AcceptableBuildingBlockConclusionCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QualifiedCertificateForWSAAtTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.CertificateQualificationConclusiveCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWAC2ExtKeyUsageCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACCertificatePolicyCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACDomainNameCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACValidityPeriodCheck;

import java.util.Date;

/**
 * This class contains common methods for performing a QWAC certificate validation
 *
 */
public abstract class AbstractQWACValidationProcessBlock extends Chain<XmlValidationQWACProcess> {

    /** Validation time */
    private final Date validationTime;

    /** The certificate to determine qualification for */
    private final CertificateWrapper certificate;

    /** Certificate's BasicBuildingBlock's conclusion */
    private final XmlConclusion buildingBlocksConclusion;

    /** Qualification validation process of the certificate */
    private final XmlCertificateQualificationProcess certificateQualification;

    /** URL of the website to validate the QWAC certificate against */
    private final String websiteUrl;

    /**
     * Common constructor
     *
     * @param i18nProvider the access to translations
     * @param validationTime {@link Date} used to perform the validation
     * @param certificate {@link CertificateWrapper} representing a TLS certificate to be validated
     * @param buildingBlocksConclusion {@link XmlConclusion}
     * @param certificateQualification {@link XmlCertificateQualificationProcess}
     * @param websiteUrl {@link String}
     */
    protected AbstractQWACValidationProcessBlock(final I18nProvider i18nProvider, final Date validationTime,
            final CertificateWrapper certificate, final XmlConclusion buildingBlocksConclusion,
            final XmlCertificateQualificationProcess certificateQualification, final String websiteUrl) {
        super(i18nProvider, new XmlValidationQWACProcess());

        result.setId(certificate.getId());

        this.certificate = certificate;
        this.validationTime = validationTime;
        this.buildingBlocksConclusion = buildingBlocksConclusion;
        this.certificateQualification = certificateQualification;
        this.websiteUrl = websiteUrl;
    }

    @Override
    protected String buildChainTitle() {
        MessageTag message = MessageTag.QWAC_VALIDATION_PROFILE;
        MessageTag param = ValidationProcessUtils.getQWACValidationMessageTag(getQWACProfile());
        return i18nProvider.getMessage(message, param);
    }

    /**
     * Gets the current QWAC profile
     *
     * @return {@link QWACProfile}
     */
    public abstract QWACProfile getQWACProfile();

    @Override
    protected void initChain() {

        /*
         * ETSI TS 119 411-5 "Policy and security requirements for Trust Service Providers issuing certificates;
         * Part 5: Implementation of qualified certificates for website authentication as in amended Regulation 910/2014"
         *
         * 6.1.2 Validation of QWACs
         *
         * For 1-QWACs and 2-QWACs, validation shall include:
         *
         * 1) that the QWAC includes QCStatements as specified in clause 4.2 of ETSI EN 319 412-4 [4] and the
         * appropriate Policy OID specified in ETSI EN 319 411-2 [3];
         *
         * 2) that the QWAC chains back through appropriate & valid digital signatures to an issuer on the EU Trusted List
         * which is authorized to issue Qualified Certificates for Website Authentication as specified in ETSI
         * TS 119 615 [1];
         */
        ChainItem<XmlValidationQWACProcess> item = firstItem = qwacCertificatePolicy();

        item = item.setNextItem(certificateQualificationConclusive());

        if (certificateQualification != null && Utils.isCollectionNotEmpty(certificateQualification.getValidationCertificateQualification())) {

            for (XmlValidationCertificateQualification certQual : certificateQualification.getValidationCertificateQualification()) {

                item = item.setNextItem(certificateForWSAAtTime(certQual));

            }

        }

        /*
         * 3) that the QWAC's validity period covers the current date and time;
         */
        item = item.setNextItem(qwacValidityPeriod());

        /*
         * 4) that the website domain name in question appears in the QWAC's subject alternative name(s); and
         */
        item = item.setNextItem(qwacDomainName());

        /*
         * 5) that the QWAC's certificate profile conforms with:
         * a) For a 1-QWAC, clause 4.1.2 of the present document; or
         * b) For a 2-QWAC, clause 4.2.2 of the present document.
         */
        // TODO: include certificate policy requirements ?

        /*
         * 4.2.2 Certificate Profile Requirements
         * The 2-QWAC certificate shall be issued in accordance with ETSI EN 319 412-4 [4] for the relevant
         * certificate policy as identified in clause 4.2.1 of the present document, except as described below:
         * • the extKeyUsage value shall only assert the extendedKeyUsage purpose of id-kp-tls-binding as specified in Annex A.
         */
        if (QWACProfile.QWAC_2 == getQWACProfile()) {
            item = item.setNextItem(qwac2ExtKeyUsage());
        }

        /*
         * The web browser may also perform further checks on the security and authenticity of the QWAC
         * as appropriate (e.g. for checking revocation status).
         */
        item = item.setNextItem(isAcceptableBuildingBlockConclusion());

    }

    private ChainItem<XmlValidationQWACProcess> certificateQualificationConclusive() {
        return new CertificateQualificationConclusiveCheck(i18nProvider, result, certificateQualification, getFailLevelRule());
    }

    private ChainItem<XmlValidationQWACProcess> certificateForWSAAtTime(XmlValidationCertificateQualification certQual) {
        return new QualifiedCertificateForWSAAtTimeCheck(i18nProvider, result, certQual, getFailLevelRule());
    }

    private ChainItem<XmlValidationQWACProcess> qwacCertificatePolicy() {
        return new QWACCertificatePolicyCheck(i18nProvider, result, certificate, getQWACProfile(), getFailLevelRule());
    }

    private ChainItem<XmlValidationQWACProcess> qwacValidityPeriod() {
        return new QWACValidityPeriodCheck(i18nProvider, result, certificate, validationTime, getFailLevelRule());
    }

    private ChainItem<XmlValidationQWACProcess> qwacDomainName() {
        return new QWACDomainNameCheck(i18nProvider, result, certificate, websiteUrl, getFailLevelRule());
    }

    private ChainItem<XmlValidationQWACProcess> qwac2ExtKeyUsage() {
        return new QWAC2ExtKeyUsageCheck(i18nProvider, result, certificate, getFailLevelRule());
    }

    private ChainItem<XmlValidationQWACProcess> isAcceptableBuildingBlockConclusion() {
        return new AcceptableBuildingBlockConclusionCheck<>(i18nProvider, result, buildingBlocksConclusion, getFailLevelRule());
    }

}
