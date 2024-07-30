package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS956ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testDSS956AllValidationLevels() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/passed_revoked_with_timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
        Reports reports = executor.execute();
        checkReports(reports);
        SimpleReport simpleReport = reports.getSimpleReport();
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));

        executor.setValidationLevel(ValidationLevel.TIMESTAMPS);
        reports = executor.execute();
        checkReports(reports);
        simpleReport = reports.getSimpleReport();
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));

        executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
        reports = executor.execute();
        checkReports(reports);
        simpleReport = reports.getSimpleReport();
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));

        executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        reports = executor.execute();
        checkReports(reports);
        simpleReport = reports.getSimpleReport();
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));
    }

}
