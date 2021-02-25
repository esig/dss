package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class XAdESLevelCAllSelfSignedTest extends XAdESLevelCTest {

    @Test
    @Override
    public void signAndVerify() {
        Exception exception = assertThrows(DSSException.class, () -> super.sign());
        assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!",
                exception.getMessage());
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service = super.getService();
        service.setTspSource(getSelfSignedTsa());
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return SELF_SIGNED_USER;
    }

}
