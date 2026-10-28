package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CBAdESAddSignaturePolicyStoreToSampleCborTest extends AbstractCBAdESTestSignature {

    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final DSSDocument SIGNATURE_POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());
    private static final String[] DOCUMENTATION_REFERENCES = new String[] { "http://docref.com/ref1", "http://docref.com/ref2" };

    private CBAdESService service;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() {
        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentToSign = new FileDocument(new File("src/test/resources/vical/vical.cbor"));
    }

    @Test
    void test() {
        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
        signaturePolicyStore.setSignaturePolicyContent(SIGNATURE_POLICY_CONTENT);
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        spDocSpec.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        spDocSpec.setDocumentationReferences(DOCUMENTATION_REFERENCES);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);

        Exception exception = assertThrows(IllegalInputException.class, () ->
                service.addSignaturePolicyStore(documentToSign, signaturePolicyStore));
        assertEquals("Not supported document", exception.getMessage());
    }

    @Override
    public void signAndVerify() {
        // skip
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return null;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
