package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignaturePolicyStoreValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void signaturePolicyStoreTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_signature_policy_store.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy policy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signatureConstraints.setSignaturePolicyStorePresent(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(policy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
    }

    @Test
    void signaturePolicyStoreNotFoundTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_signature_policy_store.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.setSignaturePolicyStore(null);

        ValidationPolicy policy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signatureConstraints.setSignaturePolicyStorePresent(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(policy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();

        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, bbb.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, bbb.getConclusion().getSubIndication());

        XmlVCI vci = bbb.getVCI();
        assertEquals(Indication.INDETERMINATE, vci.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, vci.getConclusion().getSubIndication());

        boolean signaturePolicyStoreCheckExecuted = false;
        for (XmlConstraint constraint : vci.getConstraint()) {
            if (MessageTag.BBB_VCI_ISPSUPP.name().equals(constraint.getName().getKey())) {
                signaturePolicyStoreCheckExecuted = true;
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
            }
        }
        assertTrue(signaturePolicyStoreCheckExecuted);
    }

    @Test
    void signaturePolicyNotIdentifierFailLevelTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_zero_hash_policy.xml"));
        assertNotNull(diagnosticData);

        XmlPolicy xmlPolicy = diagnosticData.getSignatures().get(0).getPolicy();
        xmlPolicy.setIdentified(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().setPolicyAvailable(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.BBB_VCI_ISPA_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, bbb.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, bbb.getConclusion().getSubIndication());

        XmlVCI vci = bbb.getVCI();
        assertEquals(Indication.INDETERMINATE, vci.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, vci.getConclusion().getSubIndication());

        boolean sigPolicyIdentifiedCheckExecuted = false;
        boolean zeroHashPolicyCheckExecuted = false;
        for (XmlConstraint constraint : vci.getConstraint()) {
            if (MessageTag.BBB_VCI_ISPA.name().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_VCI_ISPA_ANS.name(), constraint.getError().getKey());
                sigPolicyIdentifiedCheckExecuted = true;
            } else if (MessageTag.BBB_VCI_IZHSP.name().equals(constraint.getName().getKey())) {
                zeroHashPolicyCheckExecuted = true;
                assertEquals(XmlStatus.OK, constraint.getStatus());
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(sigPolicyIdentifiedCheckExecuted);
        assertFalse(zeroHashPolicyCheckExecuted);
    }

    @Test
    void signaturePolicyNotIdentifierInformLevelTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_zero_hash_policy.xml"));
        assertNotNull(diagnosticData);

        XmlPolicy xmlPolicy = diagnosticData.getSignatures().get(0).getPolicy();
        xmlPolicy.setIdentified(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.INFORM);
        validationPolicy.getSignatureConstraints().setPolicyAvailable(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.BBB_VCI_ISPA_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, bbb.getConclusion().getIndication());

        XmlVCI vci = bbb.getVCI();
        assertEquals(Indication.PASSED, vci.getConclusion().getIndication());

        boolean sigPolicyIdentifiedCheckExecuted = false;
        boolean zeroHashPolicyCheckExecuted = false;
        for (XmlConstraint constraint : vci.getConstraint()) {
            if (MessageTag.BBB_VCI_ISPA.name().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.BBB_VCI_ISPA_ANS.name(), constraint.getInfo().getKey());
                sigPolicyIdentifiedCheckExecuted = true;
            } else if (MessageTag.BBB_VCI_IZHSP.name().equals(constraint.getName().getKey())) {
                zeroHashPolicyCheckExecuted = true;
                assertEquals(XmlStatus.OK, constraint.getStatus());
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(sigPolicyIdentifiedCheckExecuted);
        assertFalse(zeroHashPolicyCheckExecuted);
    }

    @Test
    void zeroHashPolicyCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_zero_hash_policy.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, bbb.getConclusion().getIndication());

        XmlVCI vci = bbb.getVCI();
        assertEquals(Indication.PASSED, vci.getConclusion().getIndication());

        boolean sigPolicyIdentifiedCheckExecuted = false;
        boolean zeroHashPolicyCheckExecuted = false;
        for (XmlConstraint constraint : vci.getConstraint()) {
            if (MessageTag.BBB_VCI_ISPA.name().equals(constraint.getName().getKey())) {
                sigPolicyIdentifiedCheckExecuted = true;
            } else if (MessageTag.BBB_VCI_IZHSP.name().equals(constraint.getName().getKey())) {
                zeroHashPolicyCheckExecuted = true;
            }
            assertEquals(XmlStatus.OK, constraint.getStatus());
        }
        assertTrue(sigPolicyIdentifiedCheckExecuted);
        assertTrue(zeroHashPolicyCheckExecuted);
    }

}
