package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CounterSignatureValidationTest extends AbstractProcessExecutorTest {

    @Test
    void testCounterSignature() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/counter-signature-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());

        String firstSigId = simpleReport.getSignatureIdList().get(0);
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstSigId));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(firstSigId));

        String secondSigId = simpleReport.getSignatureIdList().get(1);
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(secondSigId));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(secondSigId));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(2, detailedReport.getSignatureIds().size());

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testValidCounterSignature() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/counter-signature-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());

        String firstSigId = simpleReport.getSignatureIdList().get(0);
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(firstSigId));

        String secondSigId = simpleReport.getSignatureIdList().get(1);
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(secondSigId));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testSAVWithSignatureConstraints() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/counter-signature-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        signatureConstraints.getSignedAttributes().setSignerLocation(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());

        String firstSigId = simpleReport.getSignatureIdList().get(0);
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstSigId));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(firstSigId));

        List<Message> errors = simpleReport.getAdESValidationErrors(firstSigId);
        assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_SAV_ISQPSLP_ANS)));

        String secondSigId = simpleReport.getSignatureIdList().get(1);
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(secondSigId));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testSAVWithCounterSignatureConstraints() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/counter-signature-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getCounterSignatureConstraints();
        signatureConstraints.getSignedAttributes().setContentTimeStamp(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());

        String firstSigId = simpleReport.getSignatureIdList().get(0);
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(firstSigId));

        String secondSigId = simpleReport.getSignatureIdList().get(1);
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(secondSigId));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(secondSigId));

        List<Message> errors = simpleReport.getAdESValidationErrors(secondSigId);
        assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_SAV_ISQPCTSIP_ANS)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void counterSignatureReplaceAttackTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_counter_sig_replace_attack.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignatures();
        assertEquals(1, counterSignatures.size());

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(counterSignatures.iterator().next().getId());
        assertNotNull(bbb);

        XmlCV cv = bbb.getCV();
        assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

        boolean signatureValueCheckPresentFound = false;
        boolean signatureValueCheckIntactFound = false;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_CS_CSSVF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                signatureValueCheckPresentFound = true;
            } else if (MessageTag.BBB_CV_CS_CSPS.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertNotNull(constraint.getError());
                assertEquals(MessageTag.BBB_CV_CS_CSPS_ANS.getId(), constraint.getError().getKey());
                signatureValueCheckIntactFound = true;
            }
        }
        assertTrue(signatureValueCheckPresentFound);
        assertTrue(signatureValueCheckIntactFound);
    }

    @Test
    void counterSignatureFailedFormatTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/counter-signature-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        String counterSigId = null;
        for (XmlSignature xmlSignature : diagnosticData.getSignatures()) {
            if (xmlSignature.isCounterSignature() != null && xmlSignature.isCounterSignature()) {
                xmlSignature.setSignatureFormat(SignatureLevel.XML_NOT_ETSI);
                counterSigId = xmlSignature.getId();
            }
        }
        assertNotNull(counterSigId);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints counterSignatureConstraints = validationPolicy.getCounterSignatureConstraints();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("XAdES-BASELINE-B");
        constraint.getId().add("XAdES-BASELINE-T");
        constraint.getId().add("XAdES-BASELINE-LT");
        constraint.getId().add("XAdES-BASELINE-LTA");
        constraint.setLevel(Level.FAIL);

        counterSignatureConstraints.setAcceptableFormats(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(counterSigId));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(counterSigId));

        checkReports(reports);
    }

    @Test
    void counterSignatureNoPolicyPresentTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/counter-signature-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        String counterSigId = null;
        for (XmlSignature xmlSignature : diagnosticData.getSignatures()) {
            if (xmlSignature.isCounterSignature() != null && xmlSignature.isCounterSignature()) {
                counterSigId = xmlSignature.getId();
            }
        }
        assertNotNull(counterSigId);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints counterSignatureConstraints = validationPolicy.getCounterSignatureConstraints();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("ANY_POLICY");
        constraint.setLevel(Level.FAIL);

        counterSignatureConstraints.setAcceptablePolicies(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(counterSigId));
        assertEquals(SubIndication.POLICY_PROCESSING_ERROR, simpleReport.getSubIndication(counterSigId));

        checkReports(reports);
    }

}
