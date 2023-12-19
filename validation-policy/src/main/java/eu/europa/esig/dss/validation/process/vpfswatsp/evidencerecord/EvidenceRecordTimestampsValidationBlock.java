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
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpftsp.TimestampsValidationBlock;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Verifies a time-stamp of an Evidence Record
 *
 */
public class EvidenceRecordTimestampsValidationBlock extends TimestampsValidationBlock {

    /**
     * Default constructor
     *
     * @param i18nProvider    {@link I18nProvider}
     * @param evidenceRecord  {@link EvidenceRecordWrapper}s to validate time-stamps from
     * @param diagnosticData  {@link DiagnosticData}
     * @param policy          {@link ValidationPolicy}
     * @param currentTime     {@link Date} validation time
     * @param bbbs            map of {@link XmlBasicBuildingBlocks} to fill the validation result
     * @param tlAnalysis      a list of {@link XmlTLAnalysis}
     * @param validationLevel {@link ValidationLevel} the target highest level
     */
    public EvidenceRecordTimestampsValidationBlock(final I18nProvider i18nProvider, final EvidenceRecordWrapper evidenceRecord,
                                                   final DiagnosticData diagnosticData, final ValidationPolicy policy, final Date currentTime,
                                                   final Map<String, XmlBasicBuildingBlocks> bbbs, final List<XmlTLAnalysis> tlAnalysis,
                                                   final ValidationLevel validationLevel) {
        super(i18nProvider, evidenceRecord.getTimestampList(), diagnosticData, policy, currentTime, bbbs, tlAnalysis, validationLevel);
    }

    @Override
    protected List<TimestampWrapper> getTimestamps() {
        // evidence record time-stamps are validated in the order of their appearance
        List<TimestampWrapper> timestampList = new ArrayList<>(timestamps);
        timestampList.sort(Comparator.comparing(TimestampWrapper::getProductionTime));
        return timestampList;
    }

    @Override
    protected POEExtraction getPoe(TimestampWrapper timestamp) {
        POEExtraction poe = super.getPoe(timestamp);
        /*
         * i) Before validating a time-stamp the process shall extract POEs (as per clause 5.6.2.3) of the
         * time-stamp within the next Archive timestamp and initialize the set of temporary POEs with the
         * extracted POEs.
         */
        TimestampWrapper nextTimestamp = getNextTimestamp(timestamp);
        if (nextTimestamp != null) {
            // skip message-imprint check
            poe.extractPOE(nextTimestamp.getTimestampedObjects(), nextTimestamp.getProductionTime());
        }
        return poe;
    }

    private TimestampWrapper getNextTimestamp(TimestampWrapper currentTimestamp) {
        List<TimestampWrapper> evidenceRecordTimestamps = getTimestamps();
        Iterator<TimestampWrapper> it = evidenceRecordTimestamps.iterator();
        while (it.hasNext()) {
            TimestampWrapper timestampWrapper = it.next();
            if (currentTimestamp.getId().equals(timestampWrapper.getId()) && it.hasNext()) {
                return it.next();
            }
        }
        return null;
    }

}
