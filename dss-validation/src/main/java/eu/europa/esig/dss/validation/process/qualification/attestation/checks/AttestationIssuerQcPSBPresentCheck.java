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
package eu.europa.esig.dss.validation.process.qualification.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationAttestationQualificationProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies presence of a QcPSB QcStatement
 *
 */
public class AttestationIssuerQcPSBPresentCheck extends ChainItem<XmlValidationAttestationQualificationProcess> {

    /** Signing-certificate of the attestation signature */
    private final CertificateWrapper signingCertificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationAttestationQualificationProcess}
     * @param signingCertificate {@link AttestationWrapper}
     * @param constraint {@link LevelRule}
     */
    public AttestationIssuerQcPSBPresentCheck(I18nProvider i18nProvider, XmlValidationAttestationQualificationProcess result,
                                              CertificateWrapper signingCertificate, LevelRule constraint) {
        super(i18nProvider, result, constraint);

        this.signingCertificate = signingCertificate;
    }

    @Override
    public boolean process() {
        return signingCertificate.getQcPSB() != null; // TODO : check country ?
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_QC_PSB;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_QC_PSB_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
