package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CAdESLevelERSAddSignaturePolicyStoreTest extends AbstractCAdESTestValidation {

    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final DSSDocument POLICY_CONTENT = new InMemoryDocument(
            CAdESLevelTWithSignaturePolicyStoreTest.class.getResourceAsStream("/validation/signature-policy.der"));

    private CAdESService service;
    private DSSDocument signedDocument;

    @BeforeEach
    void init() throws Exception {
        service = new CAdESService(getOfflineCertificateVerifier());
        signedDocument = new InMemoryDocument(CAdESLevelERSCounterSignatureTest.class.getResourceAsStream(
                "/validation/evidence-record/C-E-ERS.p7m"));
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
