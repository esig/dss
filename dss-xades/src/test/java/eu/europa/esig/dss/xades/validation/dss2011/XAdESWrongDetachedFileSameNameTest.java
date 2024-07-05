package eu.europa.esig.dss.xades.validation.dss2011;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESWrongDetachedFileSameNameTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2011/xades-detached.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        DSSDocument document = new FileDocument("src/test/resources/sample.png");
        document.setName("sample.xml");
        return Collections.singletonList(document);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
        assertEquals(1, originalSignerDocuments.size());

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        boolean referenceDigestMatcherFound = false;
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
                assertTrue(digestMatcher.isDataFound());
                assertFalse(digestMatcher.isDataIntact());
                assertEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod(), digestMatcher.getDigestMethod());
                assertArrayEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue(), digestMatcher.getDigestValue());
                assertEquals("sample.xml", digestMatcher.getUri());
                assertEquals("sample.xml", digestMatcher.getDocumentName());
                referenceDigestMatcherFound = true;
            }
        }
        assertTrue(referenceDigestMatcherFound);
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        assertEquals(0, originalDocuments.size());
    }

}
