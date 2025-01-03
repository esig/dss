package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESTemperedManifestValidationTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/xades-tampered-manifest.xml"));
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        List<DSSDocument> documents = new ArrayList<>();
        documents.add(new FileDocument("src/test/resources/sample.png"));
        documents.add(new FileDocument("src/test/resources/sample.txt"));
        documents.add(new FileDocument("src/test/resources/sample.xml"));
        return documents;
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSignatureIntact());
        assertFalse(signature.isSignatureValid());
        assertFalse(diagnosticData.isBLevelTechnicallyValid(signature.getId()));

        int signedPropertiesCounter = 0;
        int manifestCounter = 0;
        int manifestEntryValidCounter = 0;
        int manifestEntryInvalidCounter = 0;
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            if (DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType())) {
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                assertNotNull(digestMatcher.getUri());
                assertNull(digestMatcher.getDocumentName());
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                ++signedPropertiesCounter;

            } else if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
                assertTrue(digestMatcher.isDataFound());
                assertFalse(digestMatcher.isDataIntact());
                assertNotNull(digestMatcher.getUri());
                assertNull(digestMatcher.getDocumentName());
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                ++manifestCounter;

            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                if (digestMatcher.isDataFound()) {
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                    assertNotNull(digestMatcher.getUri());
                    assertNotNull(digestMatcher.getDocumentName());
                    assertNotNull(digestMatcher.getDigestMethod());
                    assertNotNull(digestMatcher.getDigestValue());
                    ++manifestEntryValidCounter;
                } else {
                    assertFalse(digestMatcher.isDataFound());
                    assertFalse(digestMatcher.isDataIntact());
                    assertNotNull(digestMatcher.getUri());
                    assertNotNull(digestMatcher.getDocumentName());
                    assertNull(digestMatcher.getDigestMethod());
                    assertNull(digestMatcher.getDigestValue());
                    ++manifestEntryInvalidCounter;
                }
            }
        }
        assertEquals(1, signedPropertiesCounter);
        assertEquals(1, manifestCounter);
        assertEquals(2, manifestEntryValidCounter);
        assertEquals(1, manifestEntryInvalidCounter);
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isStructuralValidationValid());
        assertTrue(signature.getStructuralValidationMessages().stream().anyMatch(m -> m.contains("ds:DigestValue"))); // not valid base64
    }

}
