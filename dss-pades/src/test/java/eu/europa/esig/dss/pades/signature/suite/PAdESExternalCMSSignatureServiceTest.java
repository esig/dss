package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.CMSForPAdESGenerationService;
import eu.europa.esig.dss.pades.signature.PAdESExternalCMSSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExternalCMSSignatureServiceTest extends PKIFactoryAccess {

    @Test
    public void test() {
        PAdESExternalCMSSignatureService service = new PAdESExternalCMSSignatureService();

        Exception exception = assertThrows(NullPointerException.class, () ->
                service.getDigestToSign(null, null));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());

        DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA256, documentToSign.getDigest(DigestAlgorithm.SHA256));

        exception = assertThrows(NullPointerException.class, () ->
                service.getDigestToSign(digestDocument, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();

        exception = assertThrows(IllegalArgumentException.class, () ->
                service.getDigestToSign(digestDocument, parameters));
        assertEquals("DigestDocument cannot be used for PAdES!", exception.getMessage());

        Digest digestToSign = service.getDigestToSign(documentToSign, parameters);
        assertNotNull(digestToSign);
        assertEquals(parameters.getDigestAlgorithm(), digestToSign.getAlgorithm());
        assertTrue(Utils.isArrayNotEmpty(digestToSign.getValue()));


        exception = assertThrows(NullPointerException.class, () ->
                service.isValidCMSSignedData(null, null));
        assertEquals("messageDigest shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () ->
                service.isValidCMSSignedData(digestToSign, null));
        assertEquals("CMSSignedDocument shall be provided!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.isValidPAdESBaselineCMSSignedData(null, null));
        assertEquals("messageDigest shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () ->
                service.isValidPAdESBaselineCMSSignedData(digestToSign, null));
        assertEquals("CMSSignedDocument shall be provided!", exception.getMessage());

        assertFalse(service.isValidCMSSignedData(digestToSign, documentToSign));
        assertFalse(service.isValidCMSSignedData(digestToSign, digestDocument));
        assertFalse(service.isValidPAdESBaselineCMSSignedData(digestToSign, documentToSign));
        assertFalse(service.isValidPAdESBaselineCMSSignedData(digestToSign, digestDocument));

        CAdESSignatureParameters cadesParameters = new CAdESSignatureParameters();
        cadesParameters.setSigningCertificate(getSigningCert());
        cadesParameters.setCertificateChain(getCertificateChain());
        cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        cadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        DigestDocument digestDocumentToSign = DSSUtils.toDigestDocument(digestToSign);
        CAdESService cadesService = new CAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = cadesService.getDataToSign(digestDocumentToSign, cadesParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, digestToSign.getAlgorithm(), getPrivateKeyEntry());
        DSSDocument cadesDetachedSignature = cadesService.signDocument(digestDocumentToSign, cadesParameters, signatureValue);

        assertFalse(service.isValidCMSSignedData(digestDocument.getExistingDigest(), cadesDetachedSignature));
        assertTrue(service.isValidCMSSignedData(digestToSign, cadesDetachedSignature));

        assertFalse(service.isValidPAdESBaselineCMSSignedData(digestToSign, cadesDetachedSignature));


        PAdESSignatureParameters cmsParameters = new PAdESSignatureParameters();
        cmsParameters.setSigningCertificate(getSigningCert());
        cmsParameters.setCertificateChain(getCertificateChain());
        cmsParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        CMSForPAdESGenerationService cmsGeneratorService = new CMSForPAdESGenerationService(getOfflineCertificateVerifier());
        dataToSign = cmsGeneratorService.getDataToSign(digestToSign, cmsParameters);
        signatureValue = getToken().sign(dataToSign, digestToSign.getAlgorithm(), getPrivateKeyEntry());
        CMSSignedDocument cmsSignature = cmsGeneratorService.getCMSSignature(digestToSign, cmsParameters, signatureValue);

        assertFalse(service.isValidCMSSignedData(digestDocument.getExistingDigest(), cmsSignature));
        assertTrue(service.isValidCMSSignedData(digestToSign, cmsSignature));

        assertTrue(service.isValidPAdESBaselineCMSSignedData(digestToSign, cmsSignature));


        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(null, null, null));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(digestDocument, null, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(digestDocument, parameters, null));
        assertEquals("SignatureLevel shall be defined within parameters!", exception.getMessage());

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(digestDocument, parameters, null));
        assertEquals("CMSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () ->
                service.signDocument(digestDocument, parameters, digestDocument));
        assertEquals("DigestDocument cannot be used for PAdES!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () ->
                service.signDocument(documentToSign, parameters, digestDocument));
        assertEquals("DigestDocument cannot be used for PAdES!", exception.getMessage());

        DSSDocument signedDocument = service.signDocument(documentToSign, parameters, cmsSignature);
        assertNotNull(signedDocument);
        validate(signedDocument, SignatureLevel.PAdES_BASELINE_B);

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(documentToSign, parameters, cmsSignature));
        assertEquals("CertificateVerifier shall be provided for PAdES extension!", exception.getMessage());

        service.setCertificateVerifier(getOfflineCertificateVerifier());
        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(documentToSign, parameters, cmsSignature));
        assertEquals("TSPSource shall be provided for PAdES extension!", exception.getMessage());

        service.setTspSource(getGoodTsa());
        signedDocument = service.signDocument(documentToSign, parameters, cmsSignature);
        assertNotNull(signedDocument);
        validate(signedDocument, SignatureLevel.PAdES_BASELINE_T);
    }

    private void validate(DSSDocument documentToValidate, SignatureLevel expectedSignatureLevel) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());

        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(expectedSignatureLevel, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper timestamp : timestampList) {
            assertTrue(timestamp.isSignatureValid());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
