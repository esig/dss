package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EvidenceRecordAloneValidationTest extends AbstractTestValidationExecutor {

    private static I18nProvider i18nProvider;

    @BeforeAll
    public static void init() {
        i18nProvider = new I18nProvider(Locale.getDefault());
    }

    @Test
    public void validERTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/er-validation/er-valid.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEvidenceRecordId())));

        for (XmlTimestamp xmlTimestamp : simpleReport.getEvidenceRecordTimestamps(simpleReport.getFirstEvidenceRecordId())) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(xmlTimestamp.getId()));
        }

        eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp firstTimestamp = diagnosticData.getUsedTimestamps().get(0);
        assertEquals(firstTimestamp.getProductionTime(), simpleReport.getEvidenceRecordPOE(simpleReport.getFirstEvidenceRecordId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getEvidenceRecordValidationIndication(detailedReport.getFirstEvidenceRecordId()));

        List<XmlEvidenceRecord> evidenceRecords = detailedReport.getIndependentEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        XmlEvidenceRecord xmlEvidenceRecord = evidenceRecords.get(0);
        assertNotNull(xmlEvidenceRecord.getId());

        XmlConclusion conclusion = xmlEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.PASSED, conclusion.getIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(i18nProvider.getMessage(MessageTag.VPER), validationProcessEvidenceRecord.getTitle());

        conclusion = validationProcessEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.PASSED, conclusion.getIndication());

        XmlProofOfExistence proofOfExistence = validationProcessEvidenceRecord.getProofOfExistence();
        assertNotNull(proofOfExistence);
        assertEquals(firstTimestamp.getId(), proofOfExistence.getTimestampId());
        assertEquals(firstTimestamp.getProductionTime(), proofOfExistence.getTime());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstCheckCounter = 0;
        int dataObjectCryptoCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                ++tstCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectCryptoCheckCounter;
            }
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
        }
        assertEquals(3, dataObjectFoundCheckCounter);
        assertEquals(3, dataObjectIntactCheckCounter);
        assertEquals(2, tstCheckCounter);
        assertEquals(3, dataObjectCryptoCheckCounter);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlEvidenceRecord.getTimestamps();
        assertEquals(2, timestamps.size());
        
        boolean indeterminateBasicTstFound = false;
        boolean passedBasicTstFound = false;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : timestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            XmlCV cv = tstBBB.getCV();
            assertNotNull(cv);

            boolean messageImprintCheckFound = false;
            boolean messageImprintIntactCheckFound = false;
            int dataObjectTstFoundCheckCounter = 0;
            int dataObjectTstIntactCheckCounter = 0;
            int tstSequenceFoundCheckCounter = 0;
            int tstSequenceIntactCheckCounter = 0;
            for (XmlConstraint xmlConstraint : cv.getConstraint()) {
                if (MessageTag.BBB_CV_TSP_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintCheckFound = true;
                } else if (MessageTag.BBB_CV_TSP_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintIntactCheckFound = true;
                } else if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstFoundCheckCounter;
                } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstIntactCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceFoundCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceIntactCheckCounter;
                }
            }
            assertTrue(messageImprintCheckFound);
            assertTrue(messageImprintIntactCheckFound);

            XmlValidationProcessBasicTimestamp basicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
            assertNotNull(basicTimestamp);
            if (Indication.PASSED.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(3, dataObjectTstFoundCheckCounter);
                assertEquals(3, dataObjectTstIntactCheckCounter);
                assertEquals(1, tstSequenceFoundCheckCounter);
                assertEquals(1, tstSequenceIntactCheckCounter);
                passedBasicTstFound = true;

            } else if (Indication.INDETERMINATE.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicTimestamp.getConclusion().getSubIndication());
                assertEquals(0, dataObjectTstFoundCheckCounter);
                assertEquals(0, dataObjectTstIntactCheckCounter);
                assertEquals(0, tstSequenceFoundCheckCounter);
                assertEquals(0, tstSequenceIntactCheckCounter);
                indeterminateBasicTstFound = true;
            }
            XmlValidationProcessArchivalDataTimestamp ltaTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertNotNull(ltaTimestamp);
            assertEquals(Indication.PASSED, ltaTimestamp.getConclusion().getIndication());

        }
        assertTrue(indeterminateBasicTstFound);
        assertTrue(passedBasicTstFound);

        checkReports(reports);
    }

    @Test
    public void brokenTstERTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/er-validation/er-valid.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getUsedTimestamps().get(1).getBasicSignature().setSignatureIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEvidenceRecordId())));

        boolean validTstFound = false;
        boolean failedTstFound = false;
        for (XmlTimestamp xmlTimestamp : simpleReport.getEvidenceRecordTimestamps(simpleReport.getFirstEvidenceRecordId())) {
            if (Indication.PASSED.equals(simpleReport.getIndication(xmlTimestamp.getId()))) {
                validTstFound = true;
            } else if (Indication.FAILED.equals(simpleReport.getIndication(xmlTimestamp.getId()))) {
                assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(xmlTimestamp.getId()));
                failedTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(failedTstFound);

        assertEquals(diagnosticData.getValidationDate(), simpleReport.getEvidenceRecordPOE(simpleReport.getFirstEvidenceRecordId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(detailedReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(detailedReport.getFirstEvidenceRecordId()));

        List<XmlEvidenceRecord> evidenceRecords = detailedReport.getIndependentEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        XmlEvidenceRecord xmlEvidenceRecord = evidenceRecords.get(0);
        assertNotNull(xmlEvidenceRecord.getId());

        XmlConclusion conclusion = xmlEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.FAILED, conclusion.getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, conclusion.getSubIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(i18nProvider.getMessage(MessageTag.VPER), validationProcessEvidenceRecord.getTitle());

        conclusion = validationProcessEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.FAILED, conclusion.getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, conclusion.getSubIndication());

        XmlProofOfExistence proofOfExistence = validationProcessEvidenceRecord.getProofOfExistence();
        assertNotNull(proofOfExistence);
        assertNull(proofOfExistence.getTimestampId());
        assertEquals(diagnosticData.getValidationDate(), proofOfExistence.getTime());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int validTstCheckCounter = 0;
        int invalidTstCheckCounter = 0;
        int dataObjectCryptoCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validTstCheckCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
                    ++invalidTstCheckCounter;
                }
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectCryptoCheckCounter;
            }
        }
        assertEquals(3, dataObjectFoundCheckCounter);
        assertEquals(3, dataObjectIntactCheckCounter);
        assertEquals(1, validTstCheckCounter);
        assertEquals(1, invalidTstCheckCounter);
        assertEquals(0, dataObjectCryptoCheckCounter); // not executed

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlEvidenceRecord.getTimestamps();
        assertEquals(2, timestamps.size());

        boolean indeterminateBasicTstFound = false;
        boolean failedBasicTstFound = false;
        boolean passedLTATstFound = false;
        boolean failedLTATstFound = false;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : timestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            XmlCV cv = tstBBB.getCV();
            assertNotNull(cv);

            boolean messageImprintCheckFound = false;
            boolean messageImprintIntactCheckFound = false;
            int dataObjectTstFoundCheckCounter = 0;
            int dataObjectTstIntactCheckCounter = 0;
            int tstSequenceFoundCheckCounter = 0;
            int tstSequenceIntactCheckCounter = 0;
            for (XmlConstraint xmlConstraint : cv.getConstraint()) {
                if (MessageTag.BBB_CV_TSP_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintCheckFound = true;
                } else if (MessageTag.BBB_CV_TSP_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintIntactCheckFound = true;
                } else if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstFoundCheckCounter;
                } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstIntactCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceFoundCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceIntactCheckCounter;
                }
            }
            assertTrue(messageImprintCheckFound);
            assertTrue(messageImprintIntactCheckFound);

            XmlValidationProcessBasicTimestamp basicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
            assertNotNull(basicTimestamp);
            if (Indication.FAILED.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.SIG_CRYPTO_FAILURE, basicTimestamp.getConclusion().getSubIndication());
                assertEquals(3, dataObjectTstFoundCheckCounter);
                assertEquals(3, dataObjectTstIntactCheckCounter);
                assertEquals(1, tstSequenceFoundCheckCounter);
                assertEquals(1, tstSequenceIntactCheckCounter);
                failedBasicTstFound = true;

            } else if (Indication.INDETERMINATE.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicTimestamp.getConclusion().getSubIndication());
                assertEquals(0, dataObjectTstFoundCheckCounter);
                assertEquals(0, dataObjectTstIntactCheckCounter);
                assertEquals(0, tstSequenceFoundCheckCounter);
                assertEquals(0, tstSequenceIntactCheckCounter);
                indeterminateBasicTstFound = true;
            }

            XmlValidationProcessArchivalDataTimestamp ltaTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertNotNull(ltaTimestamp);
            if (Indication.FAILED.equals(ltaTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.SIG_CRYPTO_FAILURE, ltaTimestamp.getConclusion().getSubIndication());
                failedLTATstFound = true;

            } else if (Indication.PASSED.equals(ltaTimestamp.getConclusion().getIndication())) {
                passedLTATstFound = true;
            }

        }
        assertTrue(indeterminateBasicTstFound);
        assertTrue(failedBasicTstFound);
        assertTrue(passedLTATstFound);
        assertTrue(failedLTATstFound);

        checkReports(reports);
    }

    @Test
    public void dataObjectRefNotFoundTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/er-validation/er-valid.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getEvidenceRecords().get(0).getDigestMatchers().get(0).setDataFound(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IRDOF_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEvidenceRecordId())));

        for (XmlTimestamp xmlTimestamp : simpleReport.getEvidenceRecordTimestamps(simpleReport.getFirstEvidenceRecordId())) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(xmlTimestamp.getId()));
        }

        eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp firstTimestamp = diagnosticData.getUsedTimestamps().get(0);
        assertEquals(firstTimestamp.getProductionTime(), simpleReport.getEvidenceRecordPOE(simpleReport.getFirstEvidenceRecordId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getEvidenceRecordValidationIndication(detailedReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getEvidenceRecordValidationSubIndication(detailedReport.getFirstEvidenceRecordId()));

        List<XmlEvidenceRecord> evidenceRecords = detailedReport.getIndependentEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        XmlEvidenceRecord xmlEvidenceRecord = evidenceRecords.get(0);
        assertNotNull(xmlEvidenceRecord.getId());

        XmlConclusion conclusion = xmlEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, conclusion.getSubIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(i18nProvider.getMessage(MessageTag.VPER), validationProcessEvidenceRecord.getTitle());

        conclusion = validationProcessEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, conclusion.getSubIndication());

        XmlProofOfExistence proofOfExistence = validationProcessEvidenceRecord.getProofOfExistence();
        assertNotNull(proofOfExistence);
        assertEquals(firstTimestamp.getId(), proofOfExistence.getTimestampId());
        assertEquals(firstTimestamp.getProductionTime(), proofOfExistence.getTime());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstCheckCounter = 0;
        int dataObjectCryptoCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_CV_IRDOF_ANS.getId(), xmlConstraint.getError().getKey());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                ++tstCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectCryptoCheckCounter;
            }
        }
        // stop at first check
        assertEquals(1, dataObjectFoundCheckCounter);
        assertEquals(0, dataObjectIntactCheckCounter);
        assertEquals(0, tstCheckCounter);
        assertEquals(0, dataObjectCryptoCheckCounter);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlEvidenceRecord.getTimestamps();
        assertEquals(2, timestamps.size());

        boolean indeterminateBasicTstFound = false;
        boolean passedBasicTstFound = false;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : timestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            XmlCV cv = tstBBB.getCV();
            assertNotNull(cv);

            boolean messageImprintCheckFound = false;
            boolean messageImprintIntactCheckFound = false;
            int dataObjectTstFoundCheckCounter = 0;
            int dataObjectTstIntactCheckCounter = 0;
            int tstSequenceFoundCheckCounter = 0;
            int tstSequenceIntactCheckCounter = 0;
            for (XmlConstraint xmlConstraint : cv.getConstraint()) {
                if (MessageTag.BBB_CV_TSP_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintCheckFound = true;
                } else if (MessageTag.BBB_CV_TSP_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintIntactCheckFound = true;
                } else if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstFoundCheckCounter;
                } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstIntactCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceFoundCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceIntactCheckCounter;
                }
            }
            assertTrue(messageImprintCheckFound);
            assertTrue(messageImprintIntactCheckFound);

            XmlValidationProcessBasicTimestamp basicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
            assertNotNull(basicTimestamp);
            if (Indication.PASSED.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(3, dataObjectTstFoundCheckCounter);
                assertEquals(3, dataObjectTstIntactCheckCounter);
                assertEquals(1, tstSequenceFoundCheckCounter);
                assertEquals(1, tstSequenceIntactCheckCounter);
                passedBasicTstFound = true;

            } else if (Indication.INDETERMINATE.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicTimestamp.getConclusion().getSubIndication());
                assertEquals(0, dataObjectTstFoundCheckCounter);
                assertEquals(0, dataObjectTstIntactCheckCounter);
                assertEquals(0, tstSequenceFoundCheckCounter);
                assertEquals(0, tstSequenceIntactCheckCounter);
                indeterminateBasicTstFound = true;
            }
            XmlValidationProcessArchivalDataTimestamp ltaTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertNotNull(ltaTimestamp);
            assertEquals(Indication.PASSED, ltaTimestamp.getConclusion().getIndication());

        }
        assertTrue(indeterminateBasicTstFound);
        assertTrue(passedBasicTstFound);

        checkReports(reports);
    }

    @Test
    public void invalidDataObjectRefTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/er-validation/er-valid.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getEvidenceRecords().get(0).getDigestMatchers().get(0).setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IRDOI_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEvidenceRecordId())));

        for (XmlTimestamp xmlTimestamp : simpleReport.getEvidenceRecordTimestamps(simpleReport.getFirstEvidenceRecordId())) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(xmlTimestamp.getId()));
        }

        eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp firstTimestamp = diagnosticData.getUsedTimestamps().get(0);
        assertEquals(firstTimestamp.getProductionTime(), simpleReport.getEvidenceRecordPOE(simpleReport.getFirstEvidenceRecordId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(detailedReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(detailedReport.getFirstEvidenceRecordId()));

        List<XmlEvidenceRecord> evidenceRecords = detailedReport.getIndependentEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        XmlEvidenceRecord xmlEvidenceRecord = evidenceRecords.get(0);
        assertNotNull(xmlEvidenceRecord.getId());

        XmlConclusion conclusion = xmlEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.FAILED, conclusion.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, conclusion.getSubIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(i18nProvider.getMessage(MessageTag.VPER), validationProcessEvidenceRecord.getTitle());

        conclusion = validationProcessEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.FAILED, conclusion.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, conclusion.getSubIndication());

        XmlProofOfExistence proofOfExistence = validationProcessEvidenceRecord.getProofOfExistence();
        assertNotNull(proofOfExistence);
        assertEquals(firstTimestamp.getId(), proofOfExistence.getTimestampId());
        assertEquals(firstTimestamp.getProductionTime(), proofOfExistence.getTime());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstCheckCounter = 0;
        int dataObjectCryptoCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_CV_IRDOI_ANS.getId(), xmlConstraint.getError().getKey());
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                ++tstCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectCryptoCheckCounter;
            }
        }
        // stop at first check
        assertEquals(1, dataObjectFoundCheckCounter);
        assertEquals(1, dataObjectIntactCheckCounter);
        assertEquals(0, tstCheckCounter);
        assertEquals(0, dataObjectCryptoCheckCounter);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlEvidenceRecord.getTimestamps();
        assertEquals(2, timestamps.size());

        boolean indeterminateBasicTstFound = false;
        boolean passedBasicTstFound = false;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : timestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            XmlCV cv = tstBBB.getCV();
            assertNotNull(cv);

            boolean messageImprintCheckFound = false;
            boolean messageImprintIntactCheckFound = false;
            int dataObjectTstFoundCheckCounter = 0;
            int dataObjectTstIntactCheckCounter = 0;
            int tstSequenceFoundCheckCounter = 0;
            int tstSequenceIntactCheckCounter = 0;
            for (XmlConstraint xmlConstraint : cv.getConstraint()) {
                if (MessageTag.BBB_CV_TSP_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintCheckFound = true;
                } else if (MessageTag.BBB_CV_TSP_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintIntactCheckFound = true;
                } else if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstFoundCheckCounter;
                } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstIntactCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceFoundCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceIntactCheckCounter;
                }
            }
            assertTrue(messageImprintCheckFound);
            assertTrue(messageImprintIntactCheckFound);

            XmlValidationProcessBasicTimestamp basicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
            assertNotNull(basicTimestamp);
            if (Indication.PASSED.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(3, dataObjectTstFoundCheckCounter);
                assertEquals(3, dataObjectTstIntactCheckCounter);
                assertEquals(1, tstSequenceFoundCheckCounter);
                assertEquals(1, tstSequenceIntactCheckCounter);
                passedBasicTstFound = true;

            } else if (Indication.INDETERMINATE.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicTimestamp.getConclusion().getSubIndication());
                assertEquals(0, dataObjectTstFoundCheckCounter);
                assertEquals(0, dataObjectTstIntactCheckCounter);
                assertEquals(0, tstSequenceFoundCheckCounter);
                assertEquals(0, tstSequenceIntactCheckCounter);
                indeterminateBasicTstFound = true;
            }
            XmlValidationProcessArchivalDataTimestamp ltaTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertNotNull(ltaTimestamp);
            assertEquals(Indication.PASSED, ltaTimestamp.getConclusion().getIndication());

        }
        assertTrue(indeterminateBasicTstFound);
        assertTrue(passedBasicTstFound);

        checkReports(reports);
    }

    @Test
    public void validERWithExpiredCryptoTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/er-validation/er-valid.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CryptographicConstraint cryptographicConstraint = validationPolicy.getEvidenceRecordCryptographicConstraint();
        AlgoExpirationDate algoExpirationDate = cryptographicConstraint.getAlgoExpirationDate();
        for (Algo algo : algoExpirationDate.getAlgos()) {
            if (DigestAlgorithm.SHA224.getName().equals(algo.getValue())) {
                algo.setDate("2022");
            }
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEvidenceRecordId())));

        for (XmlTimestamp xmlTimestamp : simpleReport.getEvidenceRecordTimestamps(simpleReport.getFirstEvidenceRecordId())) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(xmlTimestamp.getId()));
        }

        eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp firstTimestamp = diagnosticData.getUsedTimestamps().get(0);
        assertEquals(firstTimestamp.getProductionTime(), simpleReport.getEvidenceRecordPOE(simpleReport.getFirstEvidenceRecordId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getEvidenceRecordValidationIndication(detailedReport.getFirstEvidenceRecordId()));

        List<XmlEvidenceRecord> evidenceRecords = detailedReport.getIndependentEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        XmlEvidenceRecord xmlEvidenceRecord = evidenceRecords.get(0);
        assertNotNull(xmlEvidenceRecord.getId());

        XmlConclusion conclusion = xmlEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.PASSED, conclusion.getIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(i18nProvider.getMessage(MessageTag.VPER), validationProcessEvidenceRecord.getTitle());

        conclusion = validationProcessEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.PASSED, conclusion.getIndication());

        XmlProofOfExistence proofOfExistence = validationProcessEvidenceRecord.getProofOfExistence();
        assertNotNull(proofOfExistence);
        assertEquals(firstTimestamp.getId(), proofOfExistence.getTimestampId());
        assertEquals(firstTimestamp.getProductionTime(), proofOfExistence.getTime());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstCheckCounter = 0;
        int dataObjectCryptoCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                ++tstCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                ++dataObjectCryptoCheckCounter;
            }
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
        }
        assertEquals(3, dataObjectFoundCheckCounter);
        assertEquals(3, dataObjectIntactCheckCounter);
        assertEquals(2, tstCheckCounter);
        assertEquals(3, dataObjectCryptoCheckCounter);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlEvidenceRecord.getTimestamps();
        assertEquals(2, timestamps.size());

        boolean indeterminateBasicTstFound = false;
        boolean passedBasicTstFound = false;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : timestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            XmlCV cv = tstBBB.getCV();
            assertNotNull(cv);

            boolean messageImprintCheckFound = false;
            boolean messageImprintIntactCheckFound = false;
            int dataObjectTstFoundCheckCounter = 0;
            int dataObjectTstIntactCheckCounter = 0;
            int tstSequenceFoundCheckCounter = 0;
            int tstSequenceIntactCheckCounter = 0;
            for (XmlConstraint xmlConstraint : cv.getConstraint()) {
                if (MessageTag.BBB_CV_TSP_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintCheckFound = true;
                } else if (MessageTag.BBB_CV_TSP_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintIntactCheckFound = true;
                } else if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstFoundCheckCounter;
                } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstIntactCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceFoundCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceIntactCheckCounter;
                }
            }
            assertTrue(messageImprintCheckFound);
            assertTrue(messageImprintIntactCheckFound);

            XmlValidationProcessBasicTimestamp basicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
            assertNotNull(basicTimestamp);
            if (Indication.PASSED.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(3, dataObjectTstFoundCheckCounter);
                assertEquals(3, dataObjectTstIntactCheckCounter);
                assertEquals(1, tstSequenceFoundCheckCounter);
                assertEquals(1, tstSequenceIntactCheckCounter);
                passedBasicTstFound = true;

            } else if (Indication.INDETERMINATE.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicTimestamp.getConclusion().getSubIndication());
                assertEquals(0, dataObjectTstFoundCheckCounter);
                assertEquals(0, dataObjectTstIntactCheckCounter);
                assertEquals(0, tstSequenceFoundCheckCounter);
                assertEquals(0, tstSequenceIntactCheckCounter);
                indeterminateBasicTstFound = true;
            }
            XmlValidationProcessArchivalDataTimestamp ltaTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertNotNull(ltaTimestamp);
            assertEquals(Indication.PASSED, ltaTimestamp.getConclusion().getIndication());

        }
        assertTrue(indeterminateBasicTstFound);
        assertTrue(passedBasicTstFound);

        checkReports(reports);
    }

    @Test
    public void invalidERWithExpiredCryptoTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/er-validation/er-valid.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CryptographicConstraint cryptographicConstraint = validationPolicy.getEvidenceRecordCryptographicConstraint();
        AlgoExpirationDate algoExpirationDate = cryptographicConstraint.getAlgoExpirationDate();
        for (Algo algo : algoExpirationDate.getAlgos()) {
            if (DigestAlgorithm.SHA224.getName().equals(algo.getValue())) {
                algo.setDate("2020");
            }
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEvidenceRecordId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA224.getName(), MessageTag.ACCM_POS_ER_ADO)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEvidenceRecordId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEvidenceRecordId())));

        for (XmlTimestamp xmlTimestamp : simpleReport.getEvidenceRecordTimestamps(simpleReport.getFirstEvidenceRecordId())) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(xmlTimestamp.getId()));
        }

        eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp firstTimestamp = diagnosticData.getUsedTimestamps().get(0);
        assertEquals(firstTimestamp.getProductionTime(), simpleReport.getEvidenceRecordPOE(simpleReport.getFirstEvidenceRecordId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getEvidenceRecordValidationIndication(detailedReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getEvidenceRecordValidationSubIndication(detailedReport.getFirstEvidenceRecordId()));

        List<XmlEvidenceRecord> evidenceRecords = detailedReport.getIndependentEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        XmlEvidenceRecord xmlEvidenceRecord = evidenceRecords.get(0);
        assertNotNull(xmlEvidenceRecord.getId());

        XmlConclusion conclusion = xmlEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, conclusion.getSubIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(i18nProvider.getMessage(MessageTag.VPER), validationProcessEvidenceRecord.getTitle());

        conclusion = validationProcessEvidenceRecord.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, conclusion.getSubIndication());

        XmlProofOfExistence proofOfExistence = validationProcessEvidenceRecord.getProofOfExistence();
        assertNotNull(proofOfExistence);
        assertEquals(firstTimestamp.getId(), proofOfExistence.getTimestampId());
        assertEquals(firstTimestamp.getProductionTime(), proofOfExistence.getTime());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstCheckCounter = 0;
        int dataObjectCryptoCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++tstCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), xmlConstraint.getError().getKey());
                ++dataObjectCryptoCheckCounter;
            }
        }
        assertEquals(3, dataObjectFoundCheckCounter);
        assertEquals(3, dataObjectIntactCheckCounter);
        assertEquals(2, tstCheckCounter);
        assertEquals(1, dataObjectCryptoCheckCounter); // first check fails

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlEvidenceRecord.getTimestamps();
        assertEquals(2, timestamps.size());

        boolean indeterminateBasicTstFound = false;
        boolean passedBasicTstFound = false;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : timestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            XmlCV cv = tstBBB.getCV();
            assertNotNull(cv);

            boolean messageImprintCheckFound = false;
            boolean messageImprintIntactCheckFound = false;
            int dataObjectTstFoundCheckCounter = 0;
            int dataObjectTstIntactCheckCounter = 0;
            int tstSequenceFoundCheckCounter = 0;
            int tstSequenceIntactCheckCounter = 0;
            for (XmlConstraint xmlConstraint : cv.getConstraint()) {
                if (MessageTag.BBB_CV_TSP_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintCheckFound = true;
                } else if (MessageTag.BBB_CV_TSP_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNull(xmlConstraint.getAdditionalInfo());
                    messageImprintIntactCheckFound = true;
                } else if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstFoundCheckCounter;
                } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertNotNull(xmlConstraint.getAdditionalInfo());
                    ++dataObjectTstIntactCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRF.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceFoundCheckCounter;
                } else if (MessageTag.BBB_CV_ER_ATSSRI.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, MessageTag.TST_TYPE_REF_ER_ATST_SEQ), xmlConstraint.getAdditionalInfo());
                    ++tstSequenceIntactCheckCounter;
                }
            }
            assertTrue(messageImprintCheckFound);
            assertTrue(messageImprintIntactCheckFound);

            XmlValidationProcessBasicTimestamp basicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
            assertNotNull(basicTimestamp);
            if (Indication.PASSED.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(3, dataObjectTstFoundCheckCounter);
                assertEquals(3, dataObjectTstIntactCheckCounter);
                assertEquals(1, tstSequenceFoundCheckCounter);
                assertEquals(1, tstSequenceIntactCheckCounter);
                passedBasicTstFound = true;

            } else if (Indication.INDETERMINATE.equals(basicTimestamp.getConclusion().getIndication())) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicTimestamp.getConclusion().getSubIndication());
                assertEquals(0, dataObjectTstFoundCheckCounter);
                assertEquals(0, dataObjectTstIntactCheckCounter);
                assertEquals(0, tstSequenceFoundCheckCounter);
                assertEquals(0, tstSequenceIntactCheckCounter);
                indeterminateBasicTstFound = true;
            }
            XmlValidationProcessArchivalDataTimestamp ltaTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertNotNull(ltaTimestamp);
            assertEquals(Indication.PASSED, ltaTimestamp.getConclusion().getIndication());

        }
        assertTrue(indeterminateBasicTstFound);
        assertTrue(passedBasicTstFound);

        checkReports(reports);
    }

}
