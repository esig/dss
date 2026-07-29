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
package eu.europa.esig.dss.validation.process.attestation;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusionWithProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlAttestation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlLoTEAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessAttestation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.qualification.attestation.AttestationQualificationBlock;
import eu.europa.esig.dss.validation.process.qualification.signature.SignatureQualificationBlock;
import eu.europa.esig.dss.validation.process.vpfbs.BasicSignatureValidationProcess;
import eu.europa.esig.dss.validation.reports.DSSReportException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class performs validation of the attestation
 *
 */
public class AttestationValidationBlock {

    /** The i18n provider */
    private final I18nProvider i18nProvider;

    /** Diagnostic data */
    private final DiagnosticData diagnosticData;

    /** The validation policy */
    protected final ValidationPolicy policy;

    /** The validation time */
    protected final Date currentTime;

    /** Map of BasicBuildingBlocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** List of Trusted List validations */
    private final List<XmlTLAnalysis> tlAnalysis;

    /** List of List of Trusted Entities validations */
    private final List<XmlLoTEAnalysis> loteAnalysis;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param policy {@link ValidationPolicy}
     * @param currentTime {@link Date} validation time
     * @param bbbs map of {@link XmlBasicBuildingBlocks} to fill the validation result
     * @param tlAnalysis a list of {@link XmlTLAnalysis}
     * @param loteAnalysis a list of {@link XmlLoTEAnalysis}
     */
    public AttestationValidationBlock(final I18nProvider i18nProvider, final DiagnosticData diagnosticData,
                                      final ValidationPolicy policy, final Date currentTime, final Map<String, XmlBasicBuildingBlocks> bbbs,
                                      final List<XmlTLAnalysis> tlAnalysis, final List<XmlLoTEAnalysis> loteAnalysis) {
        this.i18nProvider = i18nProvider;
        this.diagnosticData = diagnosticData;
        this.policy = policy;
        this.currentTime = currentTime;
        this.bbbs = bbbs;
        this.tlAnalysis = tlAnalysis;
        this.loteAnalysis = loteAnalysis;
    }

    /**
     * Performs validation of attestation presentations
     *
     * @return a list of {@link XmlAttestation}s
     */
    public List<XmlAttestation> execute() {
        final List<XmlAttestation> result = new ArrayList<>();

        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {
            final XmlAttestation attestationAnalysis = new XmlAttestation();
            attestationAnalysis.setId(attestation.getId());

            final Map<String, XmlSignature> signatureValidationMap = new HashMap<>();

            for (SignatureWrapper signature : attestation.getAttestationSignatures()) {
                XmlSignature signatureValidation = getAttestationSignatureValidation(signature);
                attestationAnalysis.getSignature().add(signatureValidation);
                signatureValidationMap.put(signature.getId(), signatureValidation);
            }

            if (attestation.getKeyBindingSignature() != null) {
                XmlSignature signatureValidation = getAttestationSignatureValidation(attestation.getKeyBindingSignature());
                attestationAnalysis.setKeyBindingSignature(signatureValidation);
                signatureValidationMap.put(attestation.getKeyBindingSignature().getId(), signatureValidation);
            }

            AttestationValidationProcess attestationpvp = new AttestationValidationProcess(
                    i18nProvider, attestation, signatureValidationMap, bbbs, policy);
            XmlValidationProcessAttestation validationProcessAttestation = attestationpvp.execute();
            attestationAnalysis.setValidationProcessAttestation(validationProcessAttestation);

            XmlConclusion conclusion = validationProcessAttestation.getConclusion();
            attestationAnalysis.setConclusion(conclusion);

            if (policy.isEIDASConstraintPresent()) {

                for (SignatureWrapper signature : attestation.getAttestationSignatures()) {

                    XmlSignature xmlSignature = signatureValidationMap.get(signature.getId());
                    XmlValidationSignatureQualification validationSignatureQualification = getXmlValidationSignatureQualification(signature, xmlSignature);
                    xmlSignature.setValidationSignatureQualification(validationSignatureQualification);

                }

                AttestationQualificationBlock qualificationBlock = new AttestationQualificationBlock(
                        i18nProvider, attestation, conclusion, signatureValidationMap, tlAnalysis, loteAnalysis, currentTime);
                attestationAnalysis.setValidationAttestationQualification(qualificationBlock.execute());

            }

            result.add(attestationAnalysis);
        }

        return result;
    }

    private XmlSignature getAttestationSignatureValidation(SignatureWrapper signatureWrapper) {

        final XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setId(signatureWrapper.getId());

        XmlConstraintsConclusionWithProofOfExistence validation = executeBasicValidation(xmlSignature, signatureWrapper, bbbs);

        XmlConclusion conclusion = validation.getConclusion();
        conclusion.setIndication(getSignatureFinalIndication(conclusion.getIndication()));
        xmlSignature.setConclusion(conclusion);

        return xmlSignature;
    }

    private XmlValidationProcessBasicSignature executeBasicValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
                                                                      Map<String, XmlBasicBuildingBlocks> bbbs) {
        BasicSignatureValidationProcess vpfbs = new BasicSignatureValidationProcess(
                i18nProvider, diagnosticData, signature, Collections.emptyList(), bbbs);
        XmlValidationProcessBasicSignature bs = vpfbs.execute();
        signatureAnalysis.setValidationProcessBasicSignature(bs);
        return bs;
    }

    private XmlValidationSignatureQualification getXmlValidationSignatureQualification(SignatureWrapper signature, XmlSignature xmlSignature) {
        if (xmlSignature == null) {
            throw new IllegalStateException(String.format("Signature validation is not found for Id '%s'", signature.getId()));
        }

        SignatureQualificationBlock signatureQualificationBlock = new SignatureQualificationBlock(
                i18nProvider, xmlSignature.getValidationProcessBasicSignature(), signature.getSigningCertificate(), tlAnalysis);
        return signatureQualificationBlock.execute();
    }

    private Indication getSignatureFinalIndication(Indication highestIndication) {
        switch (highestIndication) {
            case PASSED:
                return Indication.TOTAL_PASSED;
            case INDETERMINATE:
                return Indication.INDETERMINATE;
            case FAILED:
                return Indication.TOTAL_FAILED;
            default:
                throw new DSSReportException(String.format("The Indication '%s' is not supported!", highestIndication));
        }
    }

}
