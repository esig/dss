package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocAttestationPresentationWithKBValidationNoSessionTranscriptTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdoc-valid.cbor");
    }

    @Override
    protected DSSDocument getSessionTranscript() {
        return null;
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean attestationSigFound = false;
        boolean kbSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertEquals(1, digestMatchers.size());
            assertEquals(DigestMatcherType.COSE_SIG_STRUCTURE, digestMatchers.get(0).getType());

            if (signatureWrapper.isKeyBindingSignature()) {
                assertFalse(digestMatchers.get(0).isDataFound());
                assertFalse(digestMatchers.get(0).isDataIntact());
                assertFalse(signatureWrapper.isBLevelTechnicallyValid());
                assertFalse(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                kbSigFound = true;

            } else {
                assertTrue(digestMatchers.get(0).isDataFound());
                assertTrue(digestMatchers.get(0).isDataIntact());
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                attestationSigFound = true;
            }
        }
        assertTrue(attestationSigFound);
        assertTrue(kbSigFound);
    }

    @Override
    protected void checkDTBSR(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
        // skip
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

}
