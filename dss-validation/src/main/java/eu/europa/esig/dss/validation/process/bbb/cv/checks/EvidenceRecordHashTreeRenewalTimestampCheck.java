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
package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;
import java.util.stream.Collectors;

/**
 * This check verifies whether the HashTree renewal time-stamp is conclusive and
 * covers all original archive data objects covered by the evidence record
 */
public class EvidenceRecordHashTreeRenewalTimestampCheck extends ChainItem<XmlCV> {

    /** Diagnostic Data */
    private final DiagnosticData diagnosticData;

    /** The time-stamp token to check */
    private final TimestampWrapper timestampWrapper;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlCV}
     * @param diagnosticData {@link DiagnosticData}
     * @param timestampWrapper {@link TimestampWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public EvidenceRecordHashTreeRenewalTimestampCheck(I18nProvider i18nProvider, XmlCV result, DiagnosticData diagnosticData,
                                                       TimestampWrapper timestampWrapper, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.diagnosticData = diagnosticData;
        this.timestampWrapper = timestampWrapper;
    }

    @Override
    protected boolean process() {
        EvidenceRecordWrapper evidenceRecord = getRelatedEvidenceRecord(timestampWrapper);
        return timestampCoversAllOriginalDocuments(evidenceRecord, timestampWrapper);
    }

    private EvidenceRecordWrapper getRelatedEvidenceRecord(TimestampWrapper timestampWrapper) {
        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            if (evidenceRecordWrapper.getTimestampList().contains(timestampWrapper)) {
                return evidenceRecordWrapper;
            }
        }
        throw new IllegalStateException(String.format(
                "Not found a corresponding evidence record for a time-stamp with Id '%s'", timestampWrapper.getId()));
    }

    private List<String> getCoveredDocuments(List<XmlDigestMatcher> digestMatchers) {
        return digestMatchers.stream().filter(d -> DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == d.getType() && d.isDataFound())
                .map(XmlDigestMatcher::getDocumentName).collect(Collectors.toList());
    }

    private boolean timestampCoversAllOriginalDocuments(EvidenceRecordWrapper evidenceRecord, TimestampWrapper timestampWrapper) {
        List<String> evidenceRecordCoveredDocuments = getCoveredDocuments(evidenceRecord.getDigestMatchers());
        List<String> timestampCoveredDocuments = getCoveredDocuments(timestampWrapper.getDigestMatchers());
        for (String originalDataObject : evidenceRecordCoveredDocuments) {
            if (!timestampCoveredDocuments.contains(originalDataObject)) {
                return false;
            }
            timestampCoveredDocuments.remove(originalDataObject); // remove object to avoid checking duplicates
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_CV_ER_TST_RN;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        if (containsOtherDigests()) {
            return MessageTag.BBB_CV_ER_TST_RN_ANS_2;
        } else {
            return MessageTag.BBB_CV_ER_TST_RN_ANS_1;
        }
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        if (containsOtherDigests()) {
            return Indication.FAILED;
        } else {
            return Indication.INDETERMINATE;
        }
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        if (containsOtherDigests()) {
            return SubIndication.HASH_FAILURE;
        } else {
            return SubIndication.SIGNED_DATA_NOT_FOUND;
        }
    }

    private boolean containsOtherDigests() {
        return timestampWrapper.getDigestMatchers().stream()
                .anyMatch(d -> DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == d.getType());
    }

}
