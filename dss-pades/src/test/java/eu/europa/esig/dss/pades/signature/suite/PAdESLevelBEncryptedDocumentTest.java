package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.pades.signature.PAdESService;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

// NOTE: encryption type is not supported in OpenPdf. See: {@link https://github.com/LibrePDF/OpenPDF/issues/375}
public class PAdESLevelBEncryptedDocumentTest extends AbstractPAdESTestSignature {

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/protected/restricted_fields.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        Exception exception = assertThrows(ProtectedDocumentException.class, () -> super.sign());
        assertEquals("The creation of new signatures is not permitted in the current document. " +
                        "Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
                        "including signature fields when document is open with user-access!",
                exception.getMessage());

        List<String> availableSignatureFields = service.getAvailableSignatureFields(documentToSign);
        assertEquals(4, availableSignatureFields.size());

        signatureParameters.getImageParameters().getTextParameters().setText("Hello World!");
        signatureParameters.getImageParameters().getFieldParameters().setFieldId(availableSignatureFields.get(0));
        return super.sign();
    }

    @Override
    protected PAdESService getService() {
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
