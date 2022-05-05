package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESWithUnsupportedSignatureAlgorithmTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-unsupported-signature-algorithm.xml");
    }

    @Test
    @Override
    public void validate() {
        Exception exception = assertThrows(DSSException.class, () -> super.validate());
        assertTrue(exception.getMessage().contains("Unable to initialize Santuario XMLSignature."));
    }

}
