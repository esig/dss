package eu.europa.esig.dss.attestation.mdoc.validation;

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

class MdocAttestationPresentationSigInvalidTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdoc-sig-invalid.cbor");
    }

    @Override
    protected DSSDocument getSessionTranscript() {
        return new InMemoryDocument(Utils.fromBase64("g9gYWFiiAGMxLjABggHYGFhLpAECIAEhWCDmILgoADAfDnPTJcLCKsri+0H8M2gJG1CZ2AGPauUViyJYIGv2G0k6HwOm/5bKiSPBeaY/aQljf2bhjfHjdJuNf2Ct2BhYS6QBAiABIVgg5iC4KAAwHw5z0yXCwirK4vtB/DNoCRtQmdgBj2rlFYsiWCBr9htJOh8Dpv+WyokjwXmmP2kJY39m4Y3x43SbjX9grYJCAQJCAwQ="));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean eaaSigFound = false;
        boolean kbSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertEquals(1, digestMatchers.size());
            assertEquals(DigestMatcherType.COSE_SIG_STRUCTURE, digestMatchers.get(0).getType());

            if (signatureWrapper.isKeyBindingSignature()) {
                assertTrue(digestMatchers.get(0).isDataFound());
                assertTrue(digestMatchers.get(0).isDataIntact());
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                kbSigFound = true;

            } else {
                assertTrue(digestMatchers.get(0).isDataFound());
                assertFalse(digestMatchers.get(0).isDataIntact());
                assertFalse(signatureWrapper.isBLevelTechnicallyValid());
                assertFalse(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                eaaSigFound = true;
            }
        }
        assertTrue(eaaSigFound);
        assertTrue(kbSigFound);
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

}
