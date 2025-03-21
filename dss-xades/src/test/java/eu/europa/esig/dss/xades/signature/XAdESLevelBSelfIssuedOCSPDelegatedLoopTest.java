package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESLevelBSelfIssuedOCSPDelegatedLoopTest extends XAdESLevelBSelfIssuedOCSPTest {

    @Override
    protected void checkRevocationAmount(DiagnosticData diagnosticData) {
        assertEquals(3, diagnosticData.getAllRevocationData().size()); // good-user + OCSP responder + CA OCSP responder
    }

    @Override
    protected String getSigningAlias() {
        return "self-issued-ocsp-delegated-loop-good-user";
    }

}
