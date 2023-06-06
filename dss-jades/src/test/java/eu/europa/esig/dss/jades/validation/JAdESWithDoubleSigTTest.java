package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESWithDoubleSigTTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-with-double-sigt.json");
    }

    @Test
    @Override
    public void validate() {
        Exception exception = assertThrows(IllegalInputException.class, super::validate);
        assertEquals("Unable to instantiate a compact JWS", exception.getMessage());
        assertTrue(exception.getCause().getMessage().contains("An entry for 'sigT' already exists."));
    }

}
