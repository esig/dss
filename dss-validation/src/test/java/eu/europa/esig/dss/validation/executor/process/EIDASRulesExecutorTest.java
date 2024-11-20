package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EIDASRulesExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testTLWrongVersion() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/commisign.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("5");
        constraint.getId().add("6");
        validationPolicy.getEIDASConstraints().setTLVersion(constraint);

        XmlTrustedList xmlTrustedList = diagnosticData.getTrustedLists().get(0);
        xmlTrustedList.setVersion(4);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        reports.print();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.NA, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_VERSION_ANS)));

        checkReports(reports);
    }

    @Test
    void testTLWrongVersionWarnLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/commisign.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.WARN);
        constraint.getId().add("5");
        constraint.getId().add("6");
        validationPolicy.getEIDASConstraints().setTLVersion(constraint);

        XmlTrustedList xmlTrustedList = diagnosticData.getTrustedLists().get(0);
        xmlTrustedList.setVersion(4);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        reports.print();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.UNKNOWN, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_VERSION_ANS)));

        checkReports(reports);
    }

}
