package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1330ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testDSS1330() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1330-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        TimestampWrapper earliestTimestamp = reports.getDiagnosticData().getTimestampById("T-950D06E9BC8B0CDB73D88349F14D3BC702BF4947752A121A940EE03639C1249D");
        TimestampWrapper secondTimestamp = reports.getDiagnosticData().getTimestampById("T-88E49182915AC09C4734996E127BFB04944E485EFC29C89D7822250A57FCC2FB");

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
        assertNotNull(signatureValidationObjects);
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationObjects.getValidationObject()));
        for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
            if (validationObject.getPOE() != null) {
                VOReferenceType poeObjectReference = validationObject.getPOE().getPOEObject();
                if (earliestTimestamp.getId().equals(validationObject.getId())) {
                    assertEquals(secondTimestamp.getProductionTime(), validationObject.getPOE().getPOETime());
                    Object poeObject = poeObjectReference.getVOReference().get(0);
                    assertInstanceOf(ValidationObjectType.class, poeObject);
                    assertEquals(secondTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
                } else if (poeObjectReference != null) {
                    assertEquals(earliestTimestamp.getProductionTime(), validationObject.getPOE().getPOETime());
                    Object poeObject = poeObjectReference.getVOReference().get(0);
                    assertInstanceOf(ValidationObjectType.class, poeObject);
                    assertEquals(earliestTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
                } else {
                    assertEquals(diagnosticData.getValidationDate(), validationObject.getPOE().getPOETime());
                }
            }
        }

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1330CryptoWarn() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1330-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadPolicyCryptoWarn());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

}
