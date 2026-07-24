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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlLoTEAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationEAAQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationEAAQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationPIDQualificationProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.AttestationQualificationProcessConclusiveCheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.checks.TrustAnchorListReachedForCertificateChainCheck;
import eu.europa.esig.dss.validation.process.qualification.eaa.pid.PIDQualificationProcessBlock;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * This class is used to verify qualification status of a signature used to create the EAA
 *
 */
public class AttestationQualificationBlock extends Chain<XmlValidationEAAQualification> {

    /** The EAA to be validated */
    private final AttestationWrapper eaa;

    /** The conclusion of EAA validation */
    private final XmlConclusion eaaConclusion;

    /** Map of signature validation processes */
    private final Map<String, XmlSignature> signatureMap;

    /** The list of all TL analyses */
    private final List<XmlTLAnalysis> tlAnalysis;

    /** List of List of Trusted Entities validations */
    private final List<XmlLoTEAnalysis> loteAnalysis;

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
     * @param loteAnalysis         a list of performed {@link XmlLoTEAnalysis}
     * @param currentTime          {@link Date}
     */
    public AttestationQualificationBlock(final I18nProvider i18nProvider, final AttestationWrapper eaa,
                                         final XmlConclusion eaaConclusion, final Map<String, XmlSignature> signatureMap,
                                         final List<XmlTLAnalysis> tlAnalysis, final List<XmlLoTEAnalysis> loteAnalysis, final Date currentTime) {
        super(i18nProvider, new XmlValidationEAAQualification());
        this.eaa = eaa;
        this.eaaConclusion = eaaConclusion;
        this.signatureMap = signatureMap;
        this.tlAnalysis = tlAnalysis;
        this.loteAnalysis = loteAnalysis;
        this.currentTime = currentTime;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.EAA_QUALIFICATION;
    }

    @Override
    protected void initChain() {

        XmlValidationEAAQualificationProcess eaaQualificationProcess = null;
        XmlValidationPIDQualificationProcess pidQualificationProcess = null;

        if (Utils.collectionSize(eaa.getEAASignatures()) == 1) {

            CertificateWrapper signingCertificate = getSigningCertificate();

            ChainItem<XmlValidationEAAQualification> item = firstItem = isTrustAnchorListReachedForCertificateChain(signingCertificate);

            AttestationQualificationProcessBlock attestationQualificationProcessBlock = new AttestationQualificationProcessBlock(
                    i18nProvider, eaa, eaaConclusion, signatureMap, tlAnalysis, currentTime);
            eaaQualificationProcess = attestationQualificationProcessBlock.execute();
            result.setValidationEAAQualificationProcess(eaaQualificationProcess);

            PIDQualificationProcessBlock pidQualificationProcessBlock = new PIDQualificationProcessBlock(
                    i18nProvider, eaa, eaaConclusion, loteAnalysis, currentTime);
            pidQualificationProcess = pidQualificationProcessBlock.execute();
            result.setValidationPIDQualificationProcess(pidQualificationProcess);

            item = item.setNextItem(eaaQualificationProcessConclusiveCheck(eaaQualificationProcess, pidQualificationProcess));

        }

        determineFinalQualification(eaaQualificationProcess, pidQualificationProcess);

    }

    private ChainItem<XmlValidationEAAQualification> isTrustAnchorListReachedForCertificateChain(CertificateWrapper signingCertificate) {
        return new TrustAnchorListReachedForCertificateChainCheck(i18nProvider, result, signingCertificate, getFailLevelRule());
    }

    private ChainItem<XmlValidationEAAQualification> eaaQualificationProcessConclusiveCheck(XmlConstraintsConclusion... conclusions) {
        return new AttestationQualificationProcessConclusiveCheck(i18nProvider, result, Arrays.asList(conclusions), getFailLevelRule());
    }

    private CertificateWrapper getSigningCertificate() {
        SignatureWrapper eaaSignature = eaa.getEAASignatures().get(0);
        return eaaSignature.getSigningCertificate();
    }

    private void determineFinalQualification(XmlValidationEAAQualificationProcess eaaQualificationProcess,
                                             XmlValidationPIDQualificationProcess pidQualificationProcess) {
        AttestationQualification attestationQualification = AttestationQualification.NA;
        if (eaaQualificationProcess != null) {
            attestationQualification = eaaQualificationProcess.getEAAQualification();
        }
        if (AttestationQualification.NA != attestationQualification) {
            result.getEAAQualification().add(attestationQualification);
        }
        AttestationQualification pidQualification = AttestationQualification.NA;
        if (pidQualificationProcess != null) {
            pidQualification = pidQualificationProcess.getEAAQualification();
        }
        if ((AttestationQualification.PID == pidQualification || AttestationQualification.INDETERMINATE_PID == pidQualification)
                && pidQualification != attestationQualification) {
            result.getEAAQualification().add(pidQualification);
        } else if ((AttestationQualification.UNKNOWN == pidQualification || AttestationQualification.INDETERMINATE_UNKNOWN == pidQualification)
                && AttestationQualification.NA == attestationQualification) {
            result.getEAAQualification().add(pidQualification);
        }
        if (Utils.isCollectionEmpty(result.getEAAQualification())) {
            result.getEAAQualification().add(AttestationQualification.NA);
        }
    }

    @Override
    protected void collectAdditionalMessages(XmlConclusion conclusion) {
        CertificateWrapper signingCertificate = getSigningCertificate();
        if (signingCertificate != null && (signingCertificate.isTrustedListReached() || signingCertificate.isListOfTrustedEntitiesReached())) {
            if (signingCertificate.isTrustedListReached()) {
                XmlValidationEAAQualificationProcess eaaQualificationProcess = result.getValidationEAAQualificationProcess();
                super.collectAllMessages(conclusion, eaaQualificationProcess.getConclusion());
            }
            if (signingCertificate.isListOfTrustedEntitiesReached()) {
                XmlValidationPIDQualificationProcess pidQualificationProcess = result.getValidationPIDQualificationProcess();
                super.collectAllMessages(conclusion, pidQualificationProcess.getConclusion());
            }
        }
    }
}
