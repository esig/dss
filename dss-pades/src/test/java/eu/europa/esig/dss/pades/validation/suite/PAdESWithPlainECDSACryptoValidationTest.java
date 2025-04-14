package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class PAdESWithPlainECDSACryptoValidationTest {

    /**
     * Positive test with default policy with PLAIN-ECDSA constrains.
     */
    @Test
    void test1() {
        DSSDocument dssDocument = new InMemoryDocument(getClass()
                .getResourceAsStream("/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf"));
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        assertNotNull(reports);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertNotNull(diagnosticData);
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(EncryptionAlgorithm.PLAIN_ECDSA, signature.getEncryptionAlgorithm());
        assertTrue(signature.isBLevelTechnicallyValid());
        assertTrue(signature.isSignatureIntact());
        assertTrue(signature.isSignatureValid());
    }

    /**
     * Negative test with policy without PLAIN-ECDSA constrains.
     */
    @Test
    void test2() {
        DSSDocument dssDocument = new InMemoryDocument(getClass()
                .getResourceAsStream("/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf"));
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument(
                getClass().getResourceAsStream("/validation/dss-PLAIN-ECDSA/policy_without_PLAIN-ECDSA.xml"));
        assertNotNull(reports);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertNotNull(diagnosticData);
        DetailedReport detailedReport = reports.getDetailedReport();
        assertNotNull(detailedReport);
        XmlBasicBuildingBlocks xmlBasicBuildingBlocks = detailedReport
                .getBasicBuildingBlockById(diagnosticData.getFirstSignatureId());
        assertNotNull(xmlBasicBuildingBlocks);
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getConclusion();
        assertNotNull(xmlConclusion);
        List<XmlMessage> messages = xmlConclusion.getErrors();
        assertNotNull(messages);
        for (XmlMessage message : messages) {
            if (MessageTag.ASCCM_EAA_ANS.name().equals(message.getKey())) {
                assertEquals(new I18nProvider().getMessage(MessageTag.ASCCM_EAA_ANS, EncryptionAlgorithm.PLAIN_ECDSA.getName(), MessageTag.ACCM_POS_SIG_SIG),
                        message.getValue());
                return;
            }
        }
        fail("NOT FOUND!");
    }

    /**
     * Negative test with default policy with PLAIN-ECDSA constrains, but a Crypto constraints without PLAIN-ECDSA.
     */
    @Test
    void test3() {
        DSSDocument dssDocument = new InMemoryDocument(getClass()
                .getResourceAsStream("/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf"));
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument(null, getClass().getResourceAsStream("/validation/dss-PLAIN-ECDSA/crypto-constraints-no-plain_ecdsa.xml"));
        assertNotNull(reports);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertNotNull(diagnosticData);
        DetailedReport detailedReport = reports.getDetailedReport();
        assertNotNull(detailedReport);
        XmlBasicBuildingBlocks xmlBasicBuildingBlocks = detailedReport
                .getBasicBuildingBlockById(diagnosticData.getFirstSignatureId());
        assertNotNull(xmlBasicBuildingBlocks);
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getConclusion();
        assertNotNull(xmlConclusion);
        List<XmlMessage> messages = xmlConclusion.getErrors();
        assertNotNull(messages);
        for (XmlMessage message : messages) {
            if (MessageTag.ASCCM_EAA_ANS.name().equals(message.getKey())) {
                assertEquals(new I18nProvider().getMessage(MessageTag.ASCCM_EAA_ANS, EncryptionAlgorithm.PLAIN_ECDSA.getName(), MessageTag.ACCM_POS_SIG_SIG),
                        message.getValue());
                return;
            }
        }
        fail("NOT FOUND!");
    }

}
