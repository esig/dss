package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.bouncycastle.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-3900
class PAdESMalformedRSAStrictDigestInfoTest extends AbstractPAdESTestValidation {

    private String original;

    @BeforeEach
    void before() {
        original = System.getProperty(Properties.PKCS1_STRICT_DIGESTINFO);
        System.setProperty(Properties.PKCS1_STRICT_DIGESTINFO, "true");
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/malformed-rsa-digestinfo.pdf"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        for (XmlDigestMatcher xmlDigestMatcher : signature.getDigestMatchers()) {
            assertTrue(xmlDigestMatcher.isDataFound());
            assertTrue(xmlDigestMatcher.isDataIntact());
        }

        assertFalse(signature.isSignatureIntact());
        assertFalse(signature.isSignatureValid());
        assertFalse(signature.isBLevelTechnicallyValid());
    }

    @AfterEach
    void after() {
        if (original == null) {
            original = "false"; // default
        }
        System.setProperty(Properties.PKCS1_STRICT_DIGESTINFO, original);
    }

}
