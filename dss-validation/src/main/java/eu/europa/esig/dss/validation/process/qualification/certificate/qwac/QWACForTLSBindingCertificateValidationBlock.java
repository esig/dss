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
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.QWAC2ValidationProcessBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks.QWAC2ValidationResultCheck;

import java.util.Date;
import java.util.Map;

/**
 * This class runs a validation process for QWAC as per ETSI TS 119 411-5 for a TLS Binding certificate
 * (e.g. 2-QWAC certificate of the TLS Certificate Binding JAdES signature)
 *
 */
public class QWACForTLSBindingCertificateValidationBlock extends Chain<XmlQWACProcess> {

    /** TLS Certificate Binding signature */
    private final SignatureWrapper bindingSignature;

    /** The certificate to determine qualification for */
    private final CertificateWrapper certificate;

    /** Validation time */
    private final Date validationTime;

    /** Map of Basic Building Blocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** Qualification status of the certificate */
    private final XmlCertificateQualificationProcess certificateQualification;

    /** URL of the website to validate the QWAC certificate against */
    private final String websiteUrl;

    /**
     * Default constructor
     *
     * @param i18nProvider the access to translations
     * @param validationTime {@link Date} used to perform the validation
     * @param bindingSignature {@link SignatureWrapper} TLS Certificate Binding signature
     * @param certificate {@link CertificateWrapper} representing a TLS certificate to be validated
     * @param bbbs map of Basic Building Blocks
     * @param certificateQualification {@link XmlCertificateQualificationProcess}
     * @param websiteUrl {@link String} representing a URL of the website in question
     */
    public QWACForTLSBindingCertificateValidationBlock(final I18nProvider i18nProvider, final Date validationTime,
               final SignatureWrapper bindingSignature, final CertificateWrapper certificate, final Map<String, XmlBasicBuildingBlocks> bbbs,
               final XmlCertificateQualificationProcess certificateQualification, final String websiteUrl) {
        super(i18nProvider, new XmlQWACProcess());

        result.setId(certificate.getId());

        this.bindingSignature = bindingSignature;
        this.certificate = certificate;
        this.validationTime = validationTime;
        this.bbbs = bbbs;
        this.certificateQualification = certificateQualification;
        this.websiteUrl = websiteUrl;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.QWAC_VALIDATION;
    }

    @Override
    protected void initChain() {

        XmlConclusion xmlConclusion = getSigningCertificateValidationProcessConclusion();
        QWAC2ValidationProcessBlock qwac2Process = new QWAC2ValidationProcessBlock(
                i18nProvider, validationTime, certificate, xmlConclusion, certificateQualification, websiteUrl);
        XmlValidationQWACProcess qwac2ValidationResult = qwac2Process.execute();
        result.getValidationQWACProcess().add(qwac2ValidationResult);

        ChainItem<XmlQWACProcess> item = firstItem = qwacValidation(qwac2ValidationResult);

        if (isValid(qwac2ValidationResult)) {
            result.setQWACType(qwac2Process.getQWACProfile());
        } else {
            result.setQWACType(QWACProfile.NOT_QWAC);
        }

    }

    private ChainItem<XmlQWACProcess> qwacValidation(XmlValidationQWACProcess... qwacValidationProcesses) {
        return new QWAC2ValidationResultCheck(i18nProvider, result, qwacValidationProcesses, getFailLevelRule());
    }

    private XmlConclusion getSigningCertificateValidationProcessConclusion() {
        XmlBasicBuildingBlocks signatureBBB = bbbs.get(bindingSignature.getId());
        if (signatureBBB == null) {
            throw new IllegalStateException(String.format("The signature basic validation process shall be performed! " +
                    "No BasicBuildingBlock found for a signature with Id '%s'", certificate.getId()));
        }

        XmlXCV xcv = signatureBBB.getXCV();
        for (XmlSubXCV subXCV : xcv.getSubXCV()) {
            if (certificate.getId().equals(subXCV.getId())) {
                return subXCV.getConclusion();
            }
        }
        return xcv.getConclusion();
    }

}
