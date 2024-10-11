package eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AbstractSignedAndTimestampedFilesCoveredCheck;

/**
 * This class verifies whether all signed and/or time-asserted file objects are subsequently covered by the evidence record
 *
 */
public class EvidenceRecordSignedAndTimestampedFilesCoveredCheck extends AbstractSignedAndTimestampedFilesCoveredCheck<XmlValidationProcessEvidenceRecord> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessEvidenceRecord}
     * @param containerInfo {@link XmlContainerInfo}
     * @param evidenceRecordWrapper {@link EvidenceRecordWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public EvidenceRecordSignedAndTimestampedFilesCoveredCheck(I18nProvider i18nProvider, XmlValidationProcessEvidenceRecord result,
            XmlContainerInfo containerInfo, EvidenceRecordWrapper evidenceRecordWrapper, LevelConstraint constraint) {
        super(i18nProvider, result, containerInfo, evidenceRecordWrapper.getFilename(), constraint);
    }

}
