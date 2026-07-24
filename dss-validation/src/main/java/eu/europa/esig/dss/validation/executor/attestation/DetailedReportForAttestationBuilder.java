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
package eu.europa.esig.dss.validation.executor.attestation;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEAA;
import eu.europa.esig.dss.detailedreport.jaxb.XmlLoTEAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.signature.DetailedReportBuilder;
import eu.europa.esig.dss.validation.process.attestation.AttestationValidationBlock;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * This class is used to perform validation of an EAA presentation validation
 *
 */
public class DetailedReportForAttestationBuilder extends DetailedReportBuilder {

    /**
     * Default constructor
     *
     * @param i18nProvider     {@link I18nProvider}
     * @param currentTime      {@link Date} validation time
     * @param policy           {@link ValidationPolicy}
     * @param diagnosticData   {@link DiagnosticData}
     * @param includeSemantics defines if the semantics shall be included
     */
    public DetailedReportForAttestationBuilder(I18nProvider i18nProvider, Date currentTime, ValidationPolicy policy,
                                               DiagnosticData diagnosticData, boolean includeSemantics) {
        super(i18nProvider, currentTime, policy, ValidationLevel.BASIC_SIGNATURES, diagnosticData, includeSemantics);
    }

    @Override
    protected void executeValidation(XmlDetailedReport detailedReport, Map<String, XmlBasicBuildingBlocks> bbbs, POEExtraction poe) {
        List<XmlEAA> eaas = executeAttestationValidations(bbbs, detailedReport.getTLAnalysis(), detailedReport.getLoTEAnalysis());
        detailedReport.getSignatureOrTimestampOrEvidenceRecord().addAll(eaas);
    }

    private List<XmlEAA> executeAttestationValidations(
            Map<String, XmlBasicBuildingBlocks> bbbs, List<XmlTLAnalysis> tlAnalysis, List<XmlLoTEAnalysis> loteAnalysis) {
        AttestationValidationBlock attestationValidationBlock = new AttestationValidationBlock(
                i18nProvider, diagnosticData, policy, currentTime, bbbs, tlAnalysis, loteAnalysis);
        return attestationValidationBlock.execute();
    }

}
