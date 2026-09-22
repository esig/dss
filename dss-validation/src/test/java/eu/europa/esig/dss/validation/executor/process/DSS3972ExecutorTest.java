package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS3972ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void dss3972Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-3972.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void dss3972FailedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-3972.xml"));
        assertNotNull(diagnosticData);

        XmlSigningCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate();
        List<XmlCertificateRevocation> revocations = signingCertificate.getCertificate().getRevocations();
        for (XmlCertificateRevocation certificateRevocation : revocations) {
            if (certificateRevocation.getRevocationDate() != null) {
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(certificateRevocation.getRevocationDate());
                calendar.add(Calendar.SECOND, -5);
                certificateRevocation.setRevocationDate(calendar.getTime());
            }
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BSV_ICTGTNASCRT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.FAILED, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED, validationProcessBasicSignature.getConclusion().getSubIndication());

        boolean xcvConclusiveFound = false;
        boolean notRevokedFound = false;
        boolean cntTstAfterRevocFound = false;
        boolean resultConclusiveFound = false;
        for (XmlConstraint xmlConstraint : validationProcessBasicSignature.getConstraint()) {
            if (MessageTag.BSV_IXCVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BSV_IXCVRC_ANS.getId(), xmlConstraint.getWarning().getKey());
                xcvConclusiveFound = true;
            } else if (MessageTag.BSV_ISCRAVTC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BSV_ISCRAVTC_ANS.getId(), xmlConstraint.getWarning().getKey());
                notRevokedFound = true;
            } else if (MessageTag.BSV_ICTGTNASCRT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BSV_ICTGTNASCRT_ANS.getId(), xmlConstraint.getWarning().getKey());
                cntTstAfterRevocFound = true;
            } else if (MessageTag.ADEST_ROBVPIIC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_ROBVPIIC_ANS.getId(), xmlConstraint.getError().getKey());
                resultConclusiveFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(xcvConclusiveFound);
        assertTrue(notRevokedFound);
        assertTrue(cntTstAfterRevocFound);
        assertTrue(resultConclusiveFound);

        checkReports(reports);
    }

}