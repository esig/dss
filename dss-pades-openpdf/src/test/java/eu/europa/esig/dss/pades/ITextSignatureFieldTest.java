package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ITextSignatureFieldTest extends PKIFactoryAccess {

    private PAdESService padesService = new PAdESService(new CommonCertificateVerifier());

    @Test
    public void testGetSignatureFields() {
        assertTrue(Utils.isCollectionNotEmpty(padesService.getAvailableSignatureFields(
                new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf")))));
    }

    @Test
    public void testAddSignatureField() throws IOException {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        assertTrue(Utils.isCollectionEmpty(padesService.getAvailableSignatureFields(document)));

        SignatureFieldParameters parameters = new SignatureFieldParameters();
        parameters.setPage(1);
        parameters.setFieldId("signature-test");
        parameters.setOriginX(50);
        parameters.setOriginY(50);
        parameters.setWidth(200);
        parameters.setHeight(200);

        DSSDocument newDocument = padesService.addNewSignatureField(document, parameters);

        List<String> availableSignatureFields = padesService.getAvailableSignatureFields(newDocument);
        assertTrue(availableSignatureFields.contains("signature-test"));

        parameters = new SignatureFieldParameters();
        parameters.setPage(1);
        parameters.setFieldId("signature-test2");
        parameters.setOriginX(300);
        parameters.setOriginY(50);
        parameters.setWidth(50);
        parameters.setHeight(50);

        DSSDocument newDocument2 = padesService.addNewSignatureField(newDocument, parameters);
        availableSignatureFields = padesService.getAvailableSignatureFields(newDocument2);
        assertEquals(2, availableSignatureFields.size());
    }

    @Test
    public void testAddSignatureFieldPageNotFound() throws IOException {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        assertTrue(Utils.isCollectionEmpty(padesService.getAvailableSignatureFields(document)));

        SignatureFieldParameters parameters = new SignatureFieldParameters();
        parameters.setPage(10);
        parameters.setFieldId("signature-test");
        parameters.setOriginX(50);
        parameters.setOriginY(50);
        parameters.setWidth(200);
        parameters.setHeight(200);

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> padesService.addNewSignatureField(document, parameters));
        assertEquals("The page number '10' does not exist in the file!", exception.getMessage());
    }

    @Test
    public void signNonSignatureFieldTest() {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

        PAdESSignatureParameters padesSignatureParameters = new PAdESSignatureParameters();
        padesSignatureParameters.setSigningCertificate(getSigningCert());
        padesSignatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        SignatureImageParameters signatureImageParameters = new SignatureImageParameters();

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setFieldId("First Name");

        signatureImageParameters.setFieldParameters(fieldParameters);
        padesSignatureParameters.setImageParameters(signatureImageParameters);

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> padesService.getDataToSign(document, padesSignatureParameters));
        assertEquals("The signature field with id 'First Name' does not exist.", exception.getMessage());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}