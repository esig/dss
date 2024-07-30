package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StructureValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void structureValidationFailureTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/xades-structure-failure.xml"));

        List<String> messages = diagnosticData.getSignatures().get(0).getStructuralValidation().getMessages();
        assertTrue(Utils.isCollectionNotEmpty(messages));

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId())); // WARN level by default

        List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_SAV_ISSV_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);

        boolean structureWarnFound = false;
        List<XmlConstraint> constraints = sav.getConstraint();
        for (XmlConstraint constraint : constraints) {
            if (MessageTag.BBB_SAV_ISSV.name().equals(constraint.getName().getKey())) {
                assertTrue(constraint.getAdditionalInfo().contains(messages.get(0)));
                structureWarnFound = true;
            }
        }
        assertTrue(structureWarnFound);
    }

    @Test
    void structuralValidationFailLevelTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/xades-structure-failure.xml"));

        List<String> messages = diagnosticData.getSignatures().get(0).getStructuralValidation().getMessages();
        assertTrue(Utils.isCollectionNotEmpty(messages));

        ValidationPolicy policy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signatureConstraints.setStructuralValidation(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(policy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_SAV_ISSV_ANS)));
    }

}
