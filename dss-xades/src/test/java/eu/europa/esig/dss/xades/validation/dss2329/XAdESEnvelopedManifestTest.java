package eu.europa.esig.dss.xades.validation.dss2329;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-2329
public class XAdESEnvelopedManifestTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2329/xades-with-enveloped-manifest.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(new FileDocument("src/test/resources/sample.png"),
                new FileDocument("src/test/resources/sample.txt"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        int manifestCounter = 0;
        int manifestRefCounter = 0;
        int emptyRefCounter = 0;
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
            if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
                ++manifestCounter;
            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                ++manifestRefCounter;
            }
            if (Utils.isStringBlank(digestMatcher.getName())) {
                ++emptyRefCounter;
            }
        }
        assertEquals(1, manifestCounter);
        assertEquals(3, manifestRefCounter);
        assertEquals(1, emptyRefCounter);
    }

}
