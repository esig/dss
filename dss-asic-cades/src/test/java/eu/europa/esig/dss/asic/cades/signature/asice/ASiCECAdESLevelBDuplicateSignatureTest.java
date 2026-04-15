package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.merge.ASiCEWithCAdESContainerMerger;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCECAdESLevelBDuplicateSignatureTest extends PKIFactoryAccess {

    private static final I18nProvider i18nProvider = new I18nProvider();

    @Test
    void test() throws Exception {
        DSSDocument document = new InMemoryDocument("Hello World !".getBytes(), "test.txt", MimeTypeEnum.TEXT);

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ToBeSigned toBeSigned = service.getDataToSign(document, signatureParameters);
        SignatureValue signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDoc = service.signDocument(document, signatureParameters, signatureValue);

        ASiCContent asicContent = new ASiCWithCAdESContainerExtractor(signedDoc).extract();
        List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
        DSSDocument originalSignatureDocument = signatureDocuments.get(0);

        DSSDocument copiedSignatureDocument = new InMemoryDocument(DSSUtils.toByteArray(originalSignatureDocument), "META-INF/signature002.p7s");
        asicContent.setSignatureDocuments(Arrays.asList(originalSignatureDocument, copiedSignatureDocument));

        DSSDocument mergedContainer = new ASiCEWithCAdESContainerMerger(asicContent).merge();

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(mergedContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(2, signatures.size());
        assertNotEquals(signatures.get(0).getId(), signatures.get(1).getId());

        boolean validSignatureFound = false;
        boolean invalidSignatureFound = false;
        for (SignatureWrapper signatureWrapper : signatures) {
            if (signatureWrapper.isBLevelTechnicallyValid()) {
                validSignatureFound = true;
            } else {
                invalidSignatureFound = true;
            }

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
        assertTrue(validSignatureFound);
        assertTrue(invalidSignatureFound);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
