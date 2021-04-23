package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ASiCWithCAdESValidateASiCXAdESTest extends AbstractASiCWithCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/signable/asic_xades.zip");
    }

    @Test
    @Override
    public void validate() {
        Exception exception = assertThrows(DSSException.class, () -> super.validate());
        assertEquals("Document format not recognized/handled", exception.getMessage());
    }

}
