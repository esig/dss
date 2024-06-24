package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLTAFailFastValidationTest extends XAdESLTATest {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);
        documentValidator.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);
        return documentValidator;
    }

    @Override
    public void validate() {
        Exception exception = assertThrows(AlertException.class, super::validate);
        assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));
    }

}
