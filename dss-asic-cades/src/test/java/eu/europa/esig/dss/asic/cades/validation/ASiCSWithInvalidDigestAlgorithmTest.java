package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSWithInvalidDigestAlgorithmTest extends AbstractASiCWithCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cades-invalid-digest-algo.asics");
    }

    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
            for (XmlDigestMatcher digestMatcher : digestMatchers) {
                if (!DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                    assertTrue(digestMatcher.isDataFound());
                    assertFalse(digestMatcher.isDataIntact());
                    assertFalse(digestMatcher.isDuplicated());
                }
            }

            assertFalse(signatureWrapper.isSignatureIntact());
            assertFalse(signatureWrapper.isSignatureValid());
            assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
        }
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean bLevelSigFound = false;
        boolean cLevelSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_B == signatureWrapper.getSignatureFormat()) {
                bLevelSigFound = true;
            } else if (SignatureLevel.CAdES_C == signatureWrapper.getSignatureFormat()) {
                cLevelSigFound = true;
            }
        }
        assertTrue(bLevelSigFound);
        assertTrue(cLevelSigFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP == timestampWrapper.getType()) {
                assertEquals(1, timestampWrapper.getDigestMatchers().size());
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, timestampWrapper.getDigestMatchers().get(0).getType());
                assertTrue(timestampWrapper.getDigestMatchers().get(0).isDataFound());
                assertTrue(timestampWrapper.getDigestMatchers().get(0).isDataIntact());

                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());

                sigTstFound = true;

            } else if (TimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getType()) {
                assertEquals(ArchiveTimestampType.CAdES_V2, timestampWrapper.getArchiveTimestampType());
                assertEquals(1, timestampWrapper.getDigestMatchers().size());
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, timestampWrapper.getDigestMatchers().get(0).getType());
                assertTrue(timestampWrapper.getDigestMatchers().get(0).isDataFound());
                assertFalse(timestampWrapper.getDigestMatchers().get(0).isDataIntact());

                assertTrue(timestampWrapper.isSignatureIntact());
                assertFalse(timestampWrapper.isSignatureValid());

                arcTstFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertEquals(0, signatureWrapper.getSignatureScopes().size());
        }
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        assertNull(signersDocument);
    }

}
