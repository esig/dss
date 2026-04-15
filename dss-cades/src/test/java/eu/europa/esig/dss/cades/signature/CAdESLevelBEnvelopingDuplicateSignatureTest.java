package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBEnvelopingDuplicateSignatureTest extends PKIFactoryAccess {

    private static final I18nProvider i18nProvider = new I18nProvider();

    @Test
    void test() throws Exception {
        DSSDocument document = new InMemoryDocument("Hello World".getBytes());

        CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        CAdESService service = new CAdESService(getOfflineCertificateVerifier());

        ToBeSigned toBeSigned = service.getDataToSign(document, signatureParameters);
        SignatureValue signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDoc = service.signDocument(document, signatureParameters, signatureValue);

        toBeSigned = service.getDataToSign(signedDoc, signatureParameters);
        signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedTwiceDoc = service.signDocument(signedDoc, signatureParameters, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedTwiceDoc);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(2, signatures.size());
        assertNotEquals(signatures.get(0).getId(), signatures.get(1).getId());

        for (SignatureWrapper signatureWrapper : signatures) {
            assertTrue(signatureWrapper.isBLevelTechnicallyValid());

            SimpleReport simpleReport = reports.getSimpleReport();
            assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(signatureWrapper.getId()));
            assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(signatureWrapper.getId()));

            DetailedReport detailedReport = reports.getDetailedReport();
            XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(signatureWrapper.getId());
            assertNotNull(signatureBBB);

            XmlFC fc = signatureBBB.getFC();
            assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
            assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());
            boolean signatureDuplicatedCheckExecuted = false;
            for (XmlConstraint constraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_ISD.name().equals(constraint.getName().getKey())) {
                    assertEquals(i18nProvider.getMessage(MessageTag.BBB_FC_ISD_ANS), constraint.getError().getValue());
                    signatureDuplicatedCheckExecuted = true;
                }
            }
            assertTrue(signatureDuplicatedCheckExecuted);

        }

    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
