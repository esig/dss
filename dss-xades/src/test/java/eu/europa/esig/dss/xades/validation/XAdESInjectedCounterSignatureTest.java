package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESInjectedCounterSignatureTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-counter-signature-injected.xml");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean counterSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                counterSignatureFound = true;

                boolean counterSignatureDMFound = false;
                boolean counterSignedSignatureDMFound = false;
                boolean signedPropertiesDMFound = false;
                assertEquals(3, signatureWrapper.getDigestMatchers().size());
                for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
                    if (DigestMatcherType.COUNTER_SIGNATURE.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        counterSignatureDMFound = true;
                    } else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        counterSignedSignatureDMFound = true;
                    } else if (DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        signedPropertiesDMFound = true;
                    }
                }
                assertTrue(counterSignatureDMFound);
                assertTrue(counterSignedSignatureDMFound);
                assertTrue(signedPropertiesDMFound);

                assertTrue(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
            }
        }
        assertTrue(counterSignatureFound);
    }

}
