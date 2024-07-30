package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashFailureExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void hashFailure() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/hash_failure.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IRDOI_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.LTV_ABSV_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(0, detailedReport.getTimestampIds().size());

        assertEquals(Indication.FAILED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.FAILED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

}
