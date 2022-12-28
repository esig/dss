package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ReferenceIdProviderTest {

    @Test
    public void defaultTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        assertEquals("r-1", referenceIdProvider.getReferenceId());
        assertEquals("r-2", referenceIdProvider.getReferenceId());
        assertEquals("r-3", referenceIdProvider.getReferenceId());
        assertEquals("r-4", referenceIdProvider.getReferenceId());
        assertEquals("r-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        assertEquals("r-1", referenceIdProvider.getReferenceId());
        assertEquals("r-2", referenceIdProvider.getReferenceId());
        assertEquals("r-3", referenceIdProvider.getReferenceId());
        assertEquals("r-4", referenceIdProvider.getReferenceId());
        assertEquals("r-5", referenceIdProvider.getReferenceId());
    }

    @Test
    public void customPrefixTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-5", referenceIdProvider.getReferenceId());
    }

    @Test
    public void signatureParamsTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());
    }

    @Test
    public void combinationParamsTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());
    }

}
