package eu.europa.esig.dss.asic.cades.extension.asice;

import eu.europa.esig.dss.asic.cades.extension.AbstractASiCWithCAdESTestExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCeExtensionWithCAdESNoSignatureZipTest extends AbstractASiCWithCAdESTestExtension {

    @Test
    @Override
    public void extendAndVerify() {
        DSSDocument document = new FileDocument("src/test/resources/signable/test.zip");
        Exception exception = assertThrows(IllegalInputException.class, () -> super.extendSignature(document));
        assertEquals("The provided file is not ASiC document!", exception.getMessage());
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_T;
    }

    @Override
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_E;
    }

}
