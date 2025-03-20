package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

class PAdESWithSelfIssuedOCSPTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-self-issued-ocsp.pdf"));
    }

}
