package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PAdESExtensionNonPDFToLTALevelTest extends AbstractPAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return null;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_LTA;
    }

    @Test
    public void test() throws Exception {
        DSSDocument documentToExtend = new InMemoryDocument(
                getClass().getResourceAsStream("/signature-image.png"), "toExtend");
        Exception exception = assertThrows(DSSException.class, () -> extendSignature(documentToExtend));
        assertEquals("Unable to extend the document with name 'toExtend'. PDF document is expected!",
                exception.getMessage());
    }

    @Override
    public void extendAndVerify() throws Exception {
    }

}
