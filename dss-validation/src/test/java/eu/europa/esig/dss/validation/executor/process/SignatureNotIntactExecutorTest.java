package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrusted;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureNotIntactExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void signatureNotIntactTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/signature-not-intact.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void multipleBBBErrorMessagesTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
        List<XmlChainItem> certificateChain = xmlSignature.getCertificateChain();
        for (XmlChainItem chainItem : certificateChain) {
            XmlCertificate certificate = chainItem.getCertificate();
            XmlTrusted xmlTrusted = new XmlTrusted();
            xmlTrusted.setValue(false);
            certificate.setTrusted(xmlTrusted);
            certificate.setSources(Arrays.asList(CertificateSourceType.OTHER));
        }
        xmlSignature.getBasicSignature().setSignatureIntact(false);
        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(false);
        xmlSignature.setStructuralValidation(xmlStructuralValidation);

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        contentTst.getBasicSignature().setSignatureIntact(false);

        List<XmlRelatedCertificate> relatedCertificates = contentTst.getFoundCertificates().getRelatedCertificates();
        for (XmlRelatedCertificate certificate : relatedCertificates) {
            certificate.getCertificateRefs().clear();
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_SIG_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ISSV_ANS)));

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp =
                simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);

        assertEquals(Indication.FAILED, xmlTimestamp.getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, xmlTimestamp.getSubIndication());
        assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getError()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_TSP_ANS)));
        assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getError()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
        assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getWarning()),
                i18nProvider.getMessage(MessageTag.BBB_ICS_ISASCP_ANS)));
    }

}
