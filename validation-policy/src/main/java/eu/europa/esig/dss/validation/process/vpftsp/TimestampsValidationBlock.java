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
package eu.europa.esig.dss.validation.process.vpftsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.process.qualification.timestamp.TimestampQualificationBlock;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpftspwatsp.ValidationProcessForTimestampsWithArchivalData;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is used to perform validation for all available timestamps,
 * as well as to extract POE information for valid entries
 *
 */
public class TimestampsValidationBlock {

    /** The i18n provider */
    private final I18nProvider i18nProvider;

    /** List of time-stamps to be validated */
    protected final List<TimestampWrapper> timestamps;

    /** The DiagnosticData to use */
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

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param timestamps a list of {@link TimestampWrapper}s to be validated
     * @param diagnosticData {@link DiagnosticData}
     * @param policy {@link ValidationPolicy}
     * @param currentTime {@link Date} validation time
     * @param bbbs map of {@link XmlBasicBuildingBlocks} to fill the validation result
     * @param tlAnalysis a list of {@link XmlTLAnalysis}
     * @param validationLevel {@link ValidationLevel} the target highest level
     * @param poe {@link POEExtraction} to be filled with POE from valid timestamps
     */
    public TimestampsValidationBlock(final I18nProvider i18nProvider, final List<TimestampWrapper> timestamps, final DiagnosticData diagnosticData,
                                     final ValidationPolicy policy, final Date currentTime, final Map<String, XmlBasicBuildingBlocks> bbbs,
                                     final List<XmlTLAnalysis> tlAnalysis, final ValidationLevel validationLevel, final POEExtraction poe) {
        this.i18nProvider = i18nProvider;
        this.timestamps = timestamps;
        this.diagnosticData = diagnosticData;
        this.policy = policy;
        this.currentTime = currentTime;
        this.bbbs = bbbs;
        this.tlAnalysis = tlAnalysis;
        this.validationLevel = validationLevel;
        this.poe = poe;
    }

    /**
     * Constructor without POE
     *
     * @param i18nProvider {@link I18nProvider}
     * @param timestamps a list of {@link TimestampWrapper}s to be validated
     * @param diagnosticData {@link DiagnosticData}
     * @param policy {@link ValidationPolicy}
     * @param currentTime {@link Date} validation time
     * @param bbbs map of {@link XmlBasicBuildingBlocks} to fill the validation result
     * @param tlAnalysis a list of {@link XmlTLAnalysis}
     * @param validationLevel {@link ValidationLevel} the target highest level
     */
    protected TimestampsValidationBlock(final I18nProvider i18nProvider, final List<TimestampWrapper> timestamps, final DiagnosticData diagnosticData,
                                     final ValidationPolicy policy, final Date currentTime, final Map<String, XmlBasicBuildingBlocks> bbbs,
                                     final List<XmlTLAnalysis> tlAnalysis, final ValidationLevel validationLevel) {
        this.i18nProvider = i18nProvider;
        this.timestamps = timestamps;
        this.diagnosticData = diagnosticData;
        this.policy = policy;
        this.currentTime = currentTime;
        this.bbbs = bbbs;
        this.tlAnalysis = tlAnalysis;
        this.validationLevel = validationLevel;
        this.poe = new POEExtraction();
        this.poe.init(diagnosticData, currentTime);
    }

    /**
     * This method performs validation of timestamps, but also fills the {@code POEExtraction} object for valid timestamps
     *
     * @return a map of {@link XmlTimestamp} identifiers and their corresponding validations
     */
    public Map<String, XmlTimestamp> execute() {
        final Map<String, XmlTimestamp> result = new HashMap<>();

        for (TimestampWrapper newestTimestamp : getTimestamps()) {
            XmlTimestamp xmlTimestamp = buildXmlTimestamp(newestTimestamp, bbbs, tlAnalysis);
            result.put(newestTimestamp.getId(), xmlTimestamp);
        }

        return result;
    }

    /**
     * Returns a list of time-stamp tokens to be validated
     *
     * @return a list of {@link TimestampWrapper}s
     */
    protected List<TimestampWrapper> getTimestamps() {
        List<TimestampWrapper> timestampList = new ArrayList<>(timestamps);
        timestampList.sort(Comparator.comparing(TimestampWrapper::getProductionTime).reversed());
        return timestampList;
    }

    private XmlTimestamp buildXmlTimestamp(TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs,
                                           List<XmlTLAnalysis> tlAnalysis) {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setId(timestamp.getId());

        POEExtraction currentPOE = getPoe(timestamp);

        TimestampBasicValidationProcess vpftsp = new TimestampBasicValidationProcess(i18nProvider, diagnosticData, timestamp, bbbs);
        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = vpftsp.execute();
        xmlTimestamp.setValidationProcessBasicTimestamp(validationProcessBasicTimestamp);

        XmlConclusion conclusion = validationProcessBasicTimestamp.getConclusion();

        // Timestamp qualification
        if (policy.isEIDASConstraintPresent()) {
            TimestampQualificationBlock timestampQualificationBlock = new TimestampQualificationBlock(
                    i18nProvider, timestamp, tlAnalysis, currentPOE);
            xmlTimestamp.setValidationTimestampQualification(timestampQualificationBlock.execute());
        }

        if (ValidationLevel.ARCHIVAL_DATA.equals(validationLevel)) {
            ValidationProcessForTimestampsWithArchivalData vpftspwatst = new ValidationProcessForTimestampsWithArchivalData(
                    i18nProvider, timestamp, validationProcessBasicTimestamp, bbbs, currentTime, policy, currentPOE);
            XmlValidationProcessArchivalDataTimestamp validationProcessTimestampArchivalData = vpftspwatst.execute();

            // extract POE for valid time-stamps
            if (validationProcessTimestampArchivalData.getConclusion() != null &&
                    Indication.PASSED == validationProcessTimestampArchivalData.getConclusion().getIndication()) {
                currentPOE.extractPOE(timestamp);
            }

            xmlTimestamp.setValidationProcessArchivalDataTimestamp(validationProcessTimestampArchivalData);
            conclusion = validationProcessTimestampArchivalData.getConclusion();
        }

        xmlTimestamp.setConclusion(conclusion);
        return xmlTimestamp;
    }

    /**
     * Returns POE object for {@code timestamp} validation
     *
     * @param timestamp {@link TimestampWrapper} to be validated
     * @return {@link POEExtraction}
     */
    protected POEExtraction getPoe(TimestampWrapper timestamp) {
        return poe;
    }

}
