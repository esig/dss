package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCSWithCAdESLevelERSAddSignaturePolicyStoreTest extends AbstractASiCWithCAdESTestValidation {

    private static final String SIGNATURE_POLICY_ID = "urn:sbr:signature-policy:xml:2.0";
    private static final DSSDocument POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());

    private ASiCWithCAdESService service;
    private DSSDocument signedDocument;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
        signedDocument = new FileDocument(new File("src/test/resources/validation/evidencerecord/cades-ers.scs"));
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return signedDocument;
    }

    @Test
    @Override
    public void validate() {
        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
        signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId(SIGNATURE_POLICY_ID);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);

        Exception exception = assertThrows(IllegalInputException.class, () -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
        assertEquals("Cannot add signature policy store to a CMS containing an evidence record unsigned attribute.", exception.getMessage());
    }

}
