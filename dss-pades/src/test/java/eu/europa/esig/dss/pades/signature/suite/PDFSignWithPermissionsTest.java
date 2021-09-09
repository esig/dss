package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PDFSignWithPermissionsTest extends AbstractPAdESTestSignature {

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    public void test() {
        // /DocMDP /P=1
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/certified-no-change-permitted.pdf"));
        Exception exception = assertThrows(AlertException.class, () -> sign());
        assertEquals("The creation of new signatures is not permitted in the current document.", exception.getMessage());

        // /DocMDP /P=2
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1188/Test.pdf"));
        DSSDocument signedDoc = sign();
        assertNotNull(signedDoc);

        // /DocMDP /P=3
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/certified-changes-permitted.pdf"));
        signedDoc = sign();
        assertNotNull(signedDoc);

        // /FieldMDP /All
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
        assertEquals("The creation of new signatures is not permitted in the current document.", exception.getMessage());

        // /FieldMDP /Include
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/fieldmdp-include.pdf"));
        signedDoc = sign();
        assertNotNull(signedDoc);

        // FieldMDP /Exclude
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/fieldmdp-exclude.pdf"));
        signedDoc = sign();
        assertNotNull(signedDoc);

        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2554/fieldmdp-exclude-signed.pdf"));
        assertEquals("The creation of new signatures is not permitted in the current document.", exception.getMessage());

        List<String> availableSignatureFields = service.getAvailableSignatureFields(documentToSign);
        assertEquals(2, availableSignatureFields.size());

        signatureParameters.getImageParameters().getFieldParameters().setFieldId(availableSignatureFields.get(0));
        signedDoc = sign();
        assertNotNull(signedDoc);
    }

    @Override
    public void signAndVerify() {
        // skip
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
