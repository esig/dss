package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PAdESLevelBNonPdfDocumentTest extends PKIFactoryAccess {

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private final DSSDocument ORIGINAL_DOCUMENT = new InMemoryDocument("Hello World !".getBytes(), "test.text");

    @BeforeEach
    public void init() throws Exception {
        documentToSign = ORIGINAL_DOCUMENT;

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getCompleteCertificateVerifier());
    }

    @Test
    public void test() {
        Exception exception = assertThrows(IllegalInputException.class,
                () -> service.getDataToSign(documentToSign, signatureParameters));
        assertEquals("The document with name 'test.text' is not a PDF. PDF document is expected!", exception.getMessage());

        exception = assertThrows(IllegalInputException.class,
                () -> service.signDocument(documentToSign, signatureParameters, new SignatureValue()));
        assertEquals("The document with name 'test.text' is not a PDF. PDF document is expected!", exception.getMessage());

        exception = assertThrows(IllegalInputException.class,
                () -> service.getContentTimestamp(documentToSign, signatureParameters));
        assertEquals("The document with name 'test.text' is not a PDF. PDF document is expected!", exception.getMessage());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
