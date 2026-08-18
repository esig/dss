package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

// See DSS-3900
// NOTE: In this test we keep the original behavior to be able to detect if logic changes in BC
class PAdESMalformedRSALaxDigestInfoTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/malformed-rsa-digestinfo.pdf"));
    }

}
