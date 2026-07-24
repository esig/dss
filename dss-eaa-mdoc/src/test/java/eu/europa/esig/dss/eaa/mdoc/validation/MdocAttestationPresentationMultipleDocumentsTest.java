package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocAttestationPresentationMultipleDocumentsTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdoc-two-documents.cbor");
    }

    @Override
    protected DSSDocument getSessionTranscript() {
        return new InMemoryDocument(Utils.fromBase64("g9gYWFiiAGMxLjABggHYGFhLpAECIAEhWCDmILgoADAfDnPTJcLCKsri+0H8M2gJG1CZ2AGPauUViyJYIGv2G0k6HwOm/5bKiSPBeaY/aQljf2bhjfHjdJuNf2Ct2BhYS6QBAiABIVgg5iC4KAAwHw5z0yXCwirK4vtB/DNoCRtQmdgBj2rlFYsiWCBr9htJOh8Dpv+WyokjwXmmP2kJY39m4Y3x43SbjX9grYJCAQJCAwQ="));
    }

    @Override
    protected int expectedEAAsCount() {
        return 2;
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        int eaaSigValidCount = 0;
        int eaaSigInvalidCount = 0;
        int kbSigValidCount = 0;
        int kbSigInvalidCount = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertEquals(1, digestMatchers.size());
            XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
            assertEquals(DigestMatcherType.COSE_SIG_STRUCTURE, xmlDigestMatcher.getType());

            if (signatureWrapper.isKeyBindingSignature()) {
                if (signatureWrapper.isBLevelTechnicallyValid()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    assertTrue(signatureWrapper.isSignatureIntact());
                    assertTrue(signatureWrapper.isSignatureValid());
                    ++kbSigValidCount;
                } else {
                    // Unmatching SessionTranscript
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertFalse(xmlDigestMatcher.isDataIntact());
                    assertFalse(signatureWrapper.isSignatureIntact());
                    assertFalse(signatureWrapper.isSignatureValid());
                    ++kbSigInvalidCount;
                }

            } else {
                if (signatureWrapper.isBLevelTechnicallyValid()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    assertTrue(signatureWrapper.isSignatureIntact());
                    assertTrue(signatureWrapper.isSignatureValid());
                    ++eaaSigValidCount;
                } else {
                    ++eaaSigInvalidCount;
                }
            }
        }
        assertEquals(2, eaaSigValidCount);
        assertEquals(0, eaaSigInvalidCount);
        assertEquals(1, kbSigValidCount);
        assertEquals(1, kbSigInvalidCount);
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

}
