package eu.europa.esig.dss.validation.process.bbb.cv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.EvidenceRecordHashTreeRenewalTimestampCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EvidenceRecordHashTreeRenewalTimestampCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        XmlDigestMatcher archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectOne);

        XmlDigestMatcher archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setName("test2");
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectTwo);

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectOne);

        archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setName("test2");
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectTwo);

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        XmlDigestMatcher archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectOne);

        XmlDigestMatcher archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setName("test2");
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectTwo);

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectOne);

        archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);
        archiveDataObjectTwo.setDataFound(false);
        archiveDataObjectTwo.setDataIntact(false);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectTwo);

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void validMoreData() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        XmlDigestMatcher archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectOne);

        XmlDigestMatcher archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);
        archiveDataObjectTwo.setDataFound(false);
        archiveDataObjectTwo.setDataIntact(false);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectTwo);

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectOne);

        archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setName("test2");
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectTwo);

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void validNoData() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidDiffData() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        XmlDigestMatcher archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectOne);

        XmlDigestMatcher archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setName("test2");
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectTwo);

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectOne);

        archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test3");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectTwo);

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void validNoName() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        XmlDigestMatcher archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectOne);

        XmlDigestMatcher archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectTwo);

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectOne);

        archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectTwo);

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidNoName() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        XmlDigestMatcher archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectOne);

        XmlDigestMatcher archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectTwo);

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectOne);

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void identifiedButNotIntact() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

        XmlDigestMatcher archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectOne);

        XmlDigestMatcher archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectTwo.setName("test2");
        archiveDataObjectTwo.setDataFound(true);
        archiveDataObjectTwo.setDataIntact(false);
        xmlEvidenceRecord.getDigestMatchers().add(archiveDataObjectTwo);

        xmlDiagnosticData.getEvidenceRecords().add(xmlEvidenceRecord);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        archiveDataObjectOne = new XmlDigestMatcher();
        archiveDataObjectOne.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        archiveDataObjectOne.setName("test1");
        archiveDataObjectOne.setDataFound(true);
        archiveDataObjectOne.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectOne);

        archiveDataObjectTwo = new XmlDigestMatcher();
        archiveDataObjectTwo.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);
        archiveDataObjectTwo.setDataFound(false);
        archiveDataObjectTwo.setDataIntact(false);
        xmlTimestamp.getDigestMatchers().add(archiveDataObjectTwo);

        XmlFoundTimestamp xmlFoundTimestamp = new XmlFoundTimestamp();
        xmlFoundTimestamp.setTimestamp(xmlTimestamp);
        xmlEvidenceRecord.getEvidenceRecordTimestamps().add(xmlFoundTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        EvidenceRecordHashTreeRenewalTimestampCheck erhtrtc = new EvidenceRecordHashTreeRenewalTimestampCheck(
                i18nProvider, result, new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), constraint);
        erhtrtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
