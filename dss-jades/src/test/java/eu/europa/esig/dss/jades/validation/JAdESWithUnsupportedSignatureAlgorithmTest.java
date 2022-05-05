package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESWithUnsupportedSignatureAlgorithmTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-unsupported-signature-algorithm.json");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSignatureIntact());
        assertFalse(signature.isSignatureValid());
        assertFalse(signature.isBLevelTechnicallyValid());
    }

    @Override
    protected void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNull(signature.getEncryptionAlgorithm());
    }

    @Override
    protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNull(signature.getDigestAlgorithm());
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(Utils.isCollectionNotEmpty(signature.getSignatureScopes()));
    }

    @Override
    protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        assertEquals(1, digestMatchers.size());

        XmlDigestMatcher digestMatcher = digestMatchers.get(0);
        assertEquals(DigestMatcherType.JWS_SIGNING_INPUT_DIGEST, digestMatcher.getType());
        assertNull(digestMatcher.getDigestMethod());
        assertFalse(Utils.isArrayNotEmpty(digestMatcher.getDigestValue()));
        assertTrue(digestMatcher.isDataFound());
        assertFalse(digestMatcher.isDataIntact());
    }

    @Override
    protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
        assertNotNull(signatureIdentifier);
        assertNotNull(signatureIdentifier.getId());
        assertNull(signatureIdentifier.getDigestAlgAndValue());
        assertNotNull(signatureIdentifier.getSignatureValue());
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        assertNull(signersDocument);
    }

}
