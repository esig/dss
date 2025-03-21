package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESLevelBSelfIssuedOCSPDelegatedTest extends XAdESLevelBSelfIssuedOCSPTest {

    @Override
    protected void checkRevocationAmount(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getAllRevocationData().size()); // good-user + OCSP responder
    }

    @Override
    protected String getSigningAlias() {
        return "self-issued-ocsp-delegated-good-user";
    }

}
