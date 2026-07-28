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
package eu.europa.esig.dss.validation.process.qualification.certificate.qwac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.QWAC1ValidationProcessBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.TLSCertificateSupportedByQWAC2ValidationProcessBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWACValidationResultCheck;

import java.util.Map;

/**
 * This class runs a validation process for QWAC as per ETSI TS 119 411-5 for a direct TLS/SSL certificate
 *
 */
public class QWACForTLSCertificateValidationBlock extends Chain<XmlQWACProcess> {

    /** Diagnostic data */
    private final DiagnosticData diagnosticData;

    /** The certificate to determine qualification for */
    private final CertificateWrapper certificate;

    /** Map of Basic Building Blocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** Qualification status of the certificate */
    private final XmlCertificateQualificationProcess certificateQualification;

    /** QWAC profile of the binding certificate */
    private final QWACProfile bindingCertificateProfile;

    /** URL of the website to validate the QWAC certificate against */
    private final String websiteUrl;

    /**
     * Default constructor
     *
     * @param i18nProvider the access to translations
     * @param diagnosticData {@link DiagnosticData} containing the validation information
     * @param certificate {@link CertificateWrapper} representing a TLS certificate to be validated
     * @param bbbs map of Basic Building Blocks
     * @param certificateQualification {@link XmlCertificateQualificationProcess}
     * @param bindingCertificateProfile {@link QWACProfile}
     * @param websiteUrl {@link String} representing a URL of the website in question
     */
    public QWACForTLSCertificateValidationBlock(final I18nProvider i18nProvider, final DiagnosticData diagnosticData,
            final CertificateWrapper certificate, final Map<String, XmlBasicBuildingBlocks> bbbs,
            final XmlCertificateQualificationProcess certificateQualification, final QWACProfile bindingCertificateProfile,
            final String websiteUrl) {
        super(i18nProvider, new XmlQWACProcess());

        result.setId(certificate.getId());

        this.certificate = certificate;
        this.diagnosticData = diagnosticData;
        this.bbbs = bbbs;
        this.certificateQualification = certificateQualification;
        this.bindingCertificateProfile = bindingCertificateProfile;
        this.websiteUrl = websiteUrl;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.QWAC_VALIDATION;
    }

    @Override
    protected void initChain() {

        XmlBasicBuildingBlocks certBBB = bbbs.get(certificate.getId());
        if (certBBB == null) {
            throw new IllegalStateException(String.format("The certificate basic validation process shall be performed! " +
                    "No BasicBuildingBlock found for a certificate with Id '%s'", certificate.getId()));
        }

        QWAC1ValidationProcessBlock qwac1Process = new QWAC1ValidationProcessBlock(
                i18nProvider, diagnosticData.getValidationDate(), certificate, certBBB.getConclusion(), certificateQualification, websiteUrl);
        XmlValidationQWACProcess qwac1ValidationResult = qwac1Process.execute();
        result.getValidationQWACProcess().add(qwac1ValidationResult);

        TLSCertificateSupportedByQWAC2ValidationProcessBlock tlsCertificateProcess =
                new TLSCertificateSupportedByQWAC2ValidationProcessBlock(i18nProvider, diagnosticData, certificate,
                        getTokenValidationConclusion(certificate), getTokenValidationConclusion(
                                diagnosticData.getTLSCertificateBindingSignature()), bindingCertificateProfile, websiteUrl);
        XmlValidationQWACProcess tlsCertificateValidationResult = tlsCertificateProcess.execute();
        result.getValidationQWACProcess().add(tlsCertificateValidationResult);

        ChainItem<XmlQWACProcess> item = firstItem = qwacValidation(qwac1ValidationResult, tlsCertificateValidationResult);

        if (isValid(qwac1ValidationResult)) {
            result.setQWACType(qwac1Process.getQWACProfile());
        } else if (isValid(tlsCertificateValidationResult)) {
            result.setQWACType(tlsCertificateProcess.getQWACProfile());
        } else {
            result.setQWACType(QWACProfile.NOT_QWAC);
        }

    }

    private ChainItem<XmlQWACProcess> qwacValidation(XmlValidationQWACProcess... qwacValidationProcesses) {
        return new QWACValidationResultCheck(i18nProvider, result, qwacValidationProcesses, getFailLevelRule());
    }

    private XmlConclusion getTokenValidationConclusion(TokenProxy token) {
        if (token != null) {
            XmlBasicBuildingBlocks bbb = bbbs.get(token.getId());
            if (bbb == null) {
                throw new IllegalStateException("The Basic validation shall be performed!");
            }
            return bbb.getConclusion();
        }
        return null;
    }

}
