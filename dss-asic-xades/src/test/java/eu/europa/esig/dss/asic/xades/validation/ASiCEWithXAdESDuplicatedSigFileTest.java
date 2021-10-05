package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class ASiCEWithXAdESDuplicatedSigFileTest extends AbstractASiCWithXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/asic-xades-duplicated-sig-file.sce");
    }

}
