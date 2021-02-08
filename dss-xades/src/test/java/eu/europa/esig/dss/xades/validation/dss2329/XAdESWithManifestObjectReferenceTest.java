package eu.europa.esig.dss.xades.validation.dss2329;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESWithManifestObjectReferenceTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2329/xades-with-manifest-with-object-reference.xml");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        int manifestCounter = 0;
        int manifestRefCounter = 0;
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
            if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
                assertEquals("r-manifest", digestMatcher.getName());
                ++manifestCounter;
            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                assertEquals("#o-id-1075588d58231c730f94fb897ed0d7a9-1", digestMatcher.getName());
                ++manifestRefCounter;
            }
        }
        assertEquals(1, manifestCounter);
        assertEquals(1, manifestRefCounter);
    }

}
