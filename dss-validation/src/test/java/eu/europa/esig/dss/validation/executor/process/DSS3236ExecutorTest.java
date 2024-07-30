package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS3236ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void digestAlgorithmCheckMergeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        assertNotNull(detailedReport);
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);

        int digestAlgorithmCheckCounter = 0;
        boolean manifestCheckFound = false;
        boolean signedPropertiesCheckFound = false;
        boolean manifestEntriesCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN))) {
                    assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
                            DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN, "")));
                    manifestCheckFound = true;
                } else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_SIGND_PRT))) {
                    assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
                            DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_SIGND_PRT, "")));
                    signedPropertiesCheckFound = true;
                } else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT_PL))) {
                    assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
                            DigestAlgorithm.SHA512.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN_ENT_PL, "")));
                    manifestEntriesCheckFound = true;
                }
                ++digestAlgorithmCheckCounter;
            }
        }
        assertEquals(5, digestAlgorithmCheckCounter); // + sig creation + signed-certificate ref check
        assertTrue(manifestCheckFound);
        assertTrue(signedPropertiesCheckFound);
        assertTrue(manifestEntriesCheckFound);
    }

    @Test
    void digestAlgorithmCheckMergeFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getSignatures().get(0).getDigestMatchers().get(2).setDigestMethod(DigestAlgorithm.SHA1);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        assertNotNull(detailedReport);
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);

        int digestAlgorithmCheckCounter = 0;
        boolean manifestCheckFound = false;
        boolean signedPropertiesCheckFound = false;
        boolean manifestEntriesCheckSuccessFound = false;
        boolean manifestEntriesCheckFailureFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN))) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
                            DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN, "")));
                    manifestCheckFound = true;
                } else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_SIGND_PRT))) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
                            DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_SIGND_PRT, "")));
                    signedPropertiesCheckFound = true;
                } else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT_PL))) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
                            DigestAlgorithm.SHA512.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN_ENT_PL, "")));
                    manifestEntriesCheckSuccessFound = true;
                } else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT))) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF_WITH_NAME,
                            i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_MAN_ENT),
                            ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), "")));
                    manifestEntriesCheckFailureFound = true;
                }
                ++digestAlgorithmCheckCounter;
            }
        }
        assertEquals(5, digestAlgorithmCheckCounter); // + sig creation (sign-cert not executed because of sha1 failure)
        assertTrue(manifestCheckFound);
        assertTrue(signedPropertiesCheckFound); // fails before
        assertTrue(manifestEntriesCheckSuccessFound);
        assertTrue(manifestEntriesCheckFailureFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);
    }

    @Test
    void erDigestAlgorithmCheckMergeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/diag_data_er_many_references.xml"));
        assertNotNull(diagnosticData);

        Date tstProductionDate = diagnosticData.getUsedTimestamps().get(0).getProductionTime();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        assertNotNull(detailedReport);
        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord =
                detailedReport.getXmlEvidenceRecordById(detailedReport.getFirstEvidenceRecordId());
        assertNotNull(xmlEvidenceRecord);
        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);

        int digestAlgorithmCheckCounter = 0;
        for (XmlConstraint constraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
                        DigestAlgorithm.SHA512.getName(), ValidationProcessUtils.getFormattedDate(tstProductionDate), MessageTag.ACCM_POS_ER_ADO_PL, "")));
                ++digestAlgorithmCheckCounter;
            }
        }
        assertEquals(1, digestAlgorithmCheckCounter);
    }

    @Test
    void erDiffDigestAlgorithmsCheckMergeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/diag_data_er_many_references.xml"));
        assertNotNull(diagnosticData);

        XmlEvidenceRecord evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        evidenceRecord.getDigestMatchers().get(0).setDigestMethod(DigestAlgorithm.SHA256);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        assertNotNull(detailedReport);
        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord =
                detailedReport.getXmlEvidenceRecordById(detailedReport.getFirstEvidenceRecordId());
        assertNotNull(xmlEvidenceRecord);
        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);

        int digestAlgorithmCheckCounter = 0;
        boolean sha256AlgoCheckFound = false;
        boolean sha512AlgoCheckFound = false;
        for (XmlConstraint constraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA256.getName())) {
                    sha256AlgoCheckFound = true;
                } else if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA512.getName())) {
                    sha512AlgoCheckFound = true;
                }
                ++digestAlgorithmCheckCounter;
            }
        }
        assertEquals(2, digestAlgorithmCheckCounter);
        assertTrue(sha256AlgoCheckFound);
        assertTrue(sha512AlgoCheckFound);
    }

    @Test
    void erDiffDigestAlgorithmsCheckMergeFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/diag_data_er_many_references.xml"));
        assertNotNull(diagnosticData);

        XmlEvidenceRecord evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        evidenceRecord.getDigestMatchers().get(0).setDigestMethod(DigestAlgorithm.SHA256);
        evidenceRecord.getDigestMatchers().get(evidenceRecord.getDigestMatchers().size() - 1).setDigestMethod(DigestAlgorithm.SHA1);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        assertNotNull(detailedReport);
        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord =
                detailedReport.getXmlEvidenceRecordById(detailedReport.getFirstEvidenceRecordId());
        assertNotNull(xmlEvidenceRecord);
        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);

        int digestAlgorithmCheckCounter = 0;
        boolean sha1AlgoCheckFound = false;
        boolean sha256AlgoCheckFound = false;
        boolean sha512AlgoCheckFound = false;
        for (XmlConstraint constraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA256.getName())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    sha256AlgoCheckFound = true;
                } else if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA512.getName())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    sha512AlgoCheckFound = true;
                } else if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA1.getName())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
                    assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_ER_ADO),
                            constraint.getError().getValue());
                    sha1AlgoCheckFound = true;
                }
                ++digestAlgorithmCheckCounter;
            }
        }
        assertEquals(3, digestAlgorithmCheckCounter);
        assertTrue(sha1AlgoCheckFound);
        assertTrue(sha256AlgoCheckFound);
        assertTrue(sha512AlgoCheckFound);
    }

}
