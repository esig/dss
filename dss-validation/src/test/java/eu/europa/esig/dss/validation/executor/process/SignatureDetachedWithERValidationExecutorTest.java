package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureDetachedWithERValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testAllFilesCovered() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-detached-with-ext-er.xml"));
        assertNotNull(diagnosticData);

        String erId = diagnosticData.getEvidenceRecords().get(0).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getEvidenceRecordConstraints().setSignedFilesCovered(constraint);

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
        boolean asicSignedContentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_ER_HASSDOC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signedContentCheckFound = true;
            } else if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                asicSignedContentCheckFound = true;
            }
        }
        assertTrue(signedContentCheckFound);
        assertFalse(asicSignedContentCheckFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testSignedFileNotCovered() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-detached-with-ext-er.xml"));
        assertNotNull(diagnosticData);

        eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord er = diagnosticData.getEvidenceRecords().get(0);
        er.getDigestMatchers().remove(1);
        String erId = er.getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getEvidenceRecordConstraints().setSignedFilesCovered(constraint);

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
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(erId));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(erId));
        assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationErrors(erId),
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(erId);
        assertNotNull(xmlEvidenceRecord);
        assertEquals(Indication.FAILED, xmlEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, xmlEvidenceRecord.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlEvidenceRecord.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        for (XmlTimestamp xmlTimestamp : xmlEvidenceRecord.getTimestamps()) {
            assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());
        }

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessEvidenceRecord.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        boolean signedContentCheckFound = false;
        boolean asicSignedContentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_ER_HASSDOC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ER_HASSDOC_ANS.getId(), xmlConstraint.getError().getKey());
                signedContentCheckFound = true;
            } else if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                asicSignedContentCheckFound = true;
            }
        }
        assertTrue(signedContentCheckFound);
        assertFalse(asicSignedContentCheckFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testSignedFileNotCoveredWarn() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-detached-with-ext-er.xml"));
        assertNotNull(diagnosticData);

        eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord er = diagnosticData.getEvidenceRecords().get(0);
        er.getDigestMatchers().remove(1);
        String erId = er.getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getEvidenceRecordConstraints().setSignedFilesCovered(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        XmlEvidenceRecord evidenceRecord = simpleReport.getEvidenceRecordById(erId);
        assertEquals(Indication.PASSED, evidenceRecord.getIndication());
        assertTrue(checkMessageValuePresence(convertMessages(evidenceRecord.getAdESValidationDetails().getWarning()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getEvidenceRecordValidationIndication(erId));
        assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationWarnings(erId),
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(erId);
        assertNotNull(xmlEvidenceRecord);
        assertEquals(Indication.PASSED, xmlEvidenceRecord.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlEvidenceRecord.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        for (XmlTimestamp xmlTimestamp : xmlEvidenceRecord.getTimestamps()) {
            assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());
        }

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(Indication.PASSED, validationProcessEvidenceRecord.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessEvidenceRecord.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ER_HASSDOC_ANS)));

        boolean signedContentCheckFound = false;
        boolean asicSignedContentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_ER_HASSDOC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ER_HASSDOC_ANS.getId(), xmlConstraint.getWarning().getKey());
                signedContentCheckFound = true;
            } else if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(xmlConstraint.getName().getKey())) {
                asicSignedContentCheckFound = true;
            }
        }
        assertTrue(signedContentCheckFound);
        assertFalse(asicSignedContentCheckFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

}
