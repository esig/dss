package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESWithDoubleSigningTimeValidationTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cades-double-signing-time.p7m");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
            for (XmlDigestMatcher digestMatcher : digestMatchers) {
                if (!DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                    assertFalse(digestMatcher.isDuplicated());
                }
            }

            if (signatureWrapper.isSignatureIntact()) {
                assertTrue(signatureWrapper.isSignatureValid());
                assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
                validSigFound = true;
            } else {
                assertFalse(signatureWrapper.isSignatureValid());
                assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_B.equals(signatureWrapper.getSignatureFormat())) {
                validSigFound = true;
            } else if (SignatureLevel.CMS_NOT_ETSI.equals(signatureWrapper.getSignatureFormat())) {
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.getClaimedSigningTime() != null) {
                validSigFound = true;
            } else {
                // value is ignored
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

}
