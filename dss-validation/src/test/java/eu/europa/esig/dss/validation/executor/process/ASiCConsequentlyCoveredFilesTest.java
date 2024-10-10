package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCConsequentlyCoveredFilesTest extends AbstractProcessExecutorTest {

    @Test
    void testAllFilesCovered() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_asic_two_tsts.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getContainerConstraints().setSignedAndTimestampedFilesCovered(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(2, simpleReport.getTimestampIdList().size());
        for (String tstId : simpleReport.getTimestampIdList()) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(tstId));
        }

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(2, detailedReport.getTimestampIds().size());
        for (String tstId : detailedReport.getTimestampIds()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(tstId);
            assertNotNull(tstBBB);
            assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

            XmlFC fc = tstBBB.getFC();
            assertNotNull(fc);
            assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

            boolean signedContentCheckFound = false;
            for (XmlConstraint xmlConstraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    signedContentCheckFound = true;
                }
            }
            assertTrue(signedContentCheckFound);
        }

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testAllFilesCoveredFail() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_asic_two_tsts.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        XmlManifestFile xmlManifestFile = containerInfo.getManifestFiles().get(0);
        xmlManifestFile.getEntries().remove(1);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getContainerConstraints().setSignedAndTimestampedFilesCovered(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(2, simpleReport.getTimestampIdList().size());

        int validTstCounter = 0;
        int invalidTstCounter = 0;
        for (String tstId : simpleReport.getTimestampIdList()) {
            if (Indication.PASSED.equals(simpleReport.getIndication(tstId))) {
                assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(tstId)));
                ++validTstCounter;

            } else if (Indication.FAILED.equals(simpleReport.getIndication(tstId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(tstId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(tstId), i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));
                ++invalidTstCounter;
            }
        }
        assertEquals(1, validTstCounter);
        assertEquals(1, invalidTstCounter);

        validTstCounter = 0;
        invalidTstCounter = 0;

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(2, detailedReport.getTimestampIds().size());
        for (String tstId : detailedReport.getTimestampIds()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(tstId);
            assertNotNull(tstBBB);

            XmlFC fc = tstBBB.getFC();
            assertNotNull(fc);

            assertEquals(tstBBB.getConclusion().getIndication(), fc.getConclusion().getIndication());

            if (Indication.PASSED.equals(tstBBB.getConclusion().getIndication())) {
                ++validTstCounter;

            } else if (Indication.FAILED.equals(tstBBB.getConclusion().getIndication())) {
                assertEquals(SubIndication.FORMAT_FAILURE, tstBBB.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(tstBBB.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));

                assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(fc.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));

                ++invalidTstCounter;
            }

            boolean signedContentCheckFound = false;
            for (XmlConstraint xmlConstraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                    if (Indication.PASSED.equals(tstBBB.getConclusion().getIndication())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    } else if (Indication.FAILED.equals(tstBBB.getConclusion().getIndication())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS.getId(), xmlConstraint.getError().getKey());
                    }
                    signedContentCheckFound = true;
                }
            }
            assertTrue(signedContentCheckFound);
        }
        assertEquals(1, validTstCounter);
        assertEquals(1, invalidTstCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testAllFilesCoveredWarn() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_asic_two_tsts.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        XmlManifestFile xmlManifestFile = containerInfo.getManifestFiles().get(0);
        xmlManifestFile.getEntries().remove(1);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getContainerConstraints().setSignedAndTimestampedFilesCovered(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(2, simpleReport.getTimestampIdList().size());

        int validTstCounter = 0;
        int invalidTstCounter = 0;
        for (String tstId : simpleReport.getTimestampIdList()) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(tstId));
            if (Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(tstId))) {
                ++validTstCounter;
            } else {
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(tstId), i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));
                ++invalidTstCounter;
            }
        }
        assertEquals(1, validTstCounter);
        assertEquals(1, invalidTstCounter);

        validTstCounter = 0;
        invalidTstCounter = 0;

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(2, detailedReport.getTimestampIds().size());
        for (String tstId : detailedReport.getTimestampIds()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(tstId);
            assertNotNull(tstBBB);

            XmlFC fc = tstBBB.getFC();
            assertNotNull(fc);

            assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());
            assertEquals(tstBBB.getConclusion().getIndication(), fc.getConclusion().getIndication());

            if (Utils.isCollectionEmpty(tstBBB.getConclusion().getWarnings())) {
                ++validTstCounter;

            } else {
                assertTrue(checkMessageValuePresence(convert(tstBBB.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));
                assertTrue(checkMessageValuePresence(convert(fc.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));

                ++invalidTstCounter;
            }

            boolean signedContentCheckFound = false;
            for (XmlConstraint xmlConstraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                    if (Utils.isCollectionEmpty(tstBBB.getConclusion().getWarnings())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    } else {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS.getId(), xmlConstraint.getWarning().getKey());
                    }
                    signedContentCheckFound = true;
                }
            }
            assertTrue(signedContentCheckFound);
        }
        assertEquals(1, validTstCounter);
        assertEquals(1, invalidTstCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testERAllFilesCovered() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/asic-sig-with-er-valid.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String erId = diagnosticData.getEvidenceRecords().get(0).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getContainerConstraints().setSignedAndTimestampedFilesCovered(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        XmlEvidenceRecord evidenceRecord = simpleReport.getEvidenceRecordById(erId);
        assertEquals(Indication.PASSED, evidenceRecord.getIndication());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getEvidenceRecordValidationIndication(erId));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(erId);
        assertNotNull(xmlEvidenceRecord);
        assertEquals(Indication.PASSED, xmlEvidenceRecord.getConclusion().getIndication());

        for (XmlTimestamp xmlTimestamp : xmlEvidenceRecord.getTimestamps()) {
            assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());
        }

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(Indication.PASSED, validationProcessEvidenceRecord.getConclusion().getIndication());

        boolean signedContentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signedContentCheckFound = true;
            }
        }
        assertTrue(signedContentCheckFound);

        XmlBasicBuildingBlocks sigTstBBB = detailedReport.getBasicBuildingBlockById(sigTstId);
        assertNotNull(sigTstBBB);

        XmlFC fc = sigTstBBB.getFC();
        assertNull(fc);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testERAllFilesCoveredFail() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/asic-sig-with-er-valid.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        XmlManifestFile xmlManifestFile = containerInfo.getManifestFiles().get(0);
        xmlManifestFile.getEntries().add("dataset/evil.xml");

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String erId = diagnosticData.getEvidenceRecords().get(0).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getContainerConstraints().setSignedAndTimestampedFilesCovered(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        XmlEvidenceRecord evidenceRecord = simpleReport.getEvidenceRecordById(erId);
        assertEquals(Indication.FAILED, evidenceRecord.getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, evidenceRecord.getSubIndication());
        assertTrue(checkMessageValuePresence(convertMessages(evidenceRecord.getAdESValidationDetails().getError()),
                i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(erId));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(erId));
        assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationErrors(erId),
                i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(erId);
        assertNotNull(xmlEvidenceRecord);
        assertEquals(Indication.FAILED, xmlEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, xmlEvidenceRecord.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlEvidenceRecord.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));

        for (XmlTimestamp xmlTimestamp : xmlEvidenceRecord.getTimestamps()) {
            assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());
        }

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessEvidenceRecord.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS)));

        boolean signedContentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS.getId(), xmlConstraint.getError().getKey());
                signedContentCheckFound = true;
            }
        }
        assertTrue(signedContentCheckFound);

        XmlBasicBuildingBlocks sigTstBBB = detailedReport.getBasicBuildingBlockById(sigTstId);
        assertNotNull(sigTstBBB);

        XmlFC fc = sigTstBBB.getFC();
        assertNull(fc);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

}
