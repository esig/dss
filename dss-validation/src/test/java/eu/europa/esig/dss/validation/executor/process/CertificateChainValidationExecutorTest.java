package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import jakarta.xml.bind.JAXB;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateChainValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testCertChain() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/qualifNA.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(1, simpleReport.getJaxbModel().getSignaturesCount());
        XmlCertificateChain certificateChain = simpleReport.getCertificateChain(simpleReport.getFirstSignatureId());
        assertNotNull(certificateChain);
        assertTrue(Utils.isCollectionNotEmpty(certificateChain.getCertificate()));
        assertEquals(3, certificateChain.getCertificate().size());
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        JAXB.marshal(simpleReport.getJaxbModel(), s);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testWithoutCertChain() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/qualifNAWithoutCertChain.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(1, simpleReport.getJaxbModel().getSignaturesCount());
        XmlCertificateChain certificateChain = simpleReport.getCertificateChain(simpleReport.getFirstSignatureId());
        assertNotNull(certificateChain);
        assertTrue(Utils.isCollectionEmpty(certificateChain.getCertificate()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void notTrustedCertChainTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        for (XmlCertificate certificate : xmlDiagnosticData.getUsedCertificates()) {
            certificate.getSources().remove(CertificateSourceType.TRUSTED_STORE);
            certificate.getTrusted().setValue(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_SIG_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, bbb.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, bbb.getConclusion().getSubIndication());

        XmlXCV xcv = bbb.getXCV();
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, xcv.getConclusion().getSubIndication());

        boolean prospectiveCertChainCheckFound = false;
        for (XmlConstraint constraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_CCCBB_SIG_ANS.getId(), constraint.getError().getKey());
                prospectiveCertChainCheckFound = true;
            }
        }
        assertTrue(prospectiveCertChainCheckFound);
        assertTrue(Utils.isCollectionEmpty(xcv.getSubXCV()));
    }

    @Test
    void notTrustedCertChainInformTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        for (XmlCertificate certificate : xmlDiagnosticData.getUsedCertificates()) {
            certificate.getSources().remove(CertificateSourceType.TRUSTED_STORE);
            certificate.getTrusted().setValue(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.INFORM);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setProspectiveCertificateChain(levelConstraint);
        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().setProspectiveCertificateChain(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_SIG_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, bbb.getConclusion().getIndication());

        XmlXCV xcv = bbb.getXCV();
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

        boolean prospectiveCertChainCheckFound = false;
        for (XmlConstraint constraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_CCCBB_SIG_ANS.getId(), constraint.getInfo().getKey());
                prospectiveCertChainCheckFound = true;
            }
        }
        assertTrue(prospectiveCertChainCheckFound);
        assertEquals(3, xcv.getSubXCV().size());
    }

}
