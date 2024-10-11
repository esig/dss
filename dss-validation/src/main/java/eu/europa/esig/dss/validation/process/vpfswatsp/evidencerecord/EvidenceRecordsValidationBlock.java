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
package eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Performs validation of all evidence records provided to the validator
 *
 */
public class EvidenceRecordsValidationBlock {

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

    /** The target highest validation level */
    private final ValidationLevel validationLevel;

    /** Contains list of all POEs */
    private final POEExtraction poe;

    /** Map of all performed time-stamp validations */
    private final Map<String, XmlTimestamp> timestampValidations = new HashMap<>();

    /** Map of all performed evidence record validations */
    private final Map<String, XmlEvidenceRecord> evidenceRecordValidations = new HashMap<>();

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param policy {@link ValidationPolicy}
     * @param currentTime {@link Date} validation time
     * @param bbbs map of {@link XmlBasicBuildingBlocks} to fill the validation result
     * @param tlAnalysis a list of {@link XmlTLAnalysis}
     * @param validationLevel {@link ValidationLevel} the target highest level
     * @param poe {@link POEExtraction}
     */
    public EvidenceRecordsValidationBlock(final I18nProvider i18nProvider, final DiagnosticData diagnosticData,
                                          final ValidationPolicy policy, final Date currentTime, final Map<String, XmlBasicBuildingBlocks> bbbs,
                                          final List<XmlTLAnalysis> tlAnalysis, final ValidationLevel validationLevel, final POEExtraction poe) {
        this.i18nProvider = i18nProvider;
        this.diagnosticData = diagnosticData;
        this.policy = policy;
        this.currentTime = currentTime;
        this.bbbs = bbbs;
        this.tlAnalysis = tlAnalysis;
        this.validationLevel = validationLevel;
        this.poe = poe;
    }

    /**
     * Performs validation of evidence records
     */
    public void execute() {
        for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {
            final XmlEvidenceRecord evidenceRecordAnalysis = new XmlEvidenceRecord();
            evidenceRecordAnalysis.setId(evidenceRecord.getId());

            EvidenceRecordTimestampsValidationBlock allTimestampValidationBlock = new EvidenceRecordTimestampsValidationBlock(
                    i18nProvider, evidenceRecord, diagnosticData, policy, currentTime, bbbs, tlAnalysis, validationLevel);
            Map<String, XmlTimestamp> currentTimestampValidations = allTimestampValidationBlock.execute();
            timestampValidations.putAll(currentTimestampValidations);

            evidenceRecordAnalysis.getTimestamps().addAll(currentTimestampValidations.values());

            EvidenceRecordValidationProcess ervp = new EvidenceRecordValidationProcess(
                    i18nProvider, diagnosticData, evidenceRecord, currentTimestampValidations.values(), bbbs, policy, currentTime);
            XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = ervp.execute();
            evidenceRecordAnalysis.setValidationProcessEvidenceRecord(validationProcessEvidenceRecord);

            XmlConclusion conclusion = validationProcessEvidenceRecord.getConclusion();
            evidenceRecordAnalysis.setConclusion(conclusion);

            if (conclusion != null && Indication.PASSED == conclusion.getIndication()) {
                poe.extractPOE(evidenceRecord);
            }

            evidenceRecordValidations.put(evidenceRecord.getId(), evidenceRecordAnalysis);
        }
    }

    /**
     * Returns a map of performed time-stamp validations
     *
     * @return a map of time-stamp identifiers and their corresponding validations
     */
    public Map<String, XmlTimestamp> getTimestampValidations() {
        return timestampValidations;
    }

    /**
     * Returns a map of performed evidence record validations
     *
     * @return a map of evidence record identifiers and their corresponding validations
     */
    public Map<String, XmlEvidenceRecord> getEvidenceRecordValidations() {
        return evidenceRecordValidations;
    }

}
