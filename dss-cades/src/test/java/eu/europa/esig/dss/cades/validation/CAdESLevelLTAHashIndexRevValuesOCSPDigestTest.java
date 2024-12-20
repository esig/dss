package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelLTAHashIndexRevValuesOCSPDigestTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cades-ats-v3-rev-val-ocsp.p7s");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_C, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        assertEquals(3, diagnosticData.getTimestampList().size());

        boolean sigTstFound = false;
        boolean arcTstV2Found = false;
        boolean arcTstV3Found = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP == timestampWrapper.getType()) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());

                assertNull(timestampWrapper.getAtsHashIndexVersion());

                sigTstFound = true;

            } else if (TimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getType()) {
                if (ArchiveTimestampType.CAdES_V2 == timestampWrapper.getArchiveTimestampType()) {
                    assertTrue(timestampWrapper.isMessageImprintDataFound());
                    assertTrue(timestampWrapper.isMessageImprintDataIntact());
                    assertTrue(timestampWrapper.isSignatureIntact());
                    assertTrue(timestampWrapper.isSignatureValid());

                    assertNull(timestampWrapper.getAtsHashIndexVersion());
                    arcTstV2Found = true;

                } else if (ArchiveTimestampType.CAdES_V3 == timestampWrapper.getArchiveTimestampType()) {
                    assertTrue(timestampWrapper.isMessageImprintDataFound());
                    assertTrue(timestampWrapper.isMessageImprintDataIntact());
                    assertTrue(timestampWrapper.isSignatureIntact());
                    assertTrue(timestampWrapper.isSignatureValid());

                    assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3, timestampWrapper.getAtsHashIndexVersion());
                    assertFalse(timestampWrapper.isAtsHashIndexValid());
                    assertFalse(Utils.isCollectionEmpty(timestampWrapper.getAtsHashIndexValidationMessages()));
                    assertTrue(timestampWrapper.getAtsHashIndexValidationMessages().contains(
                            "ats-hash-index attribute contains crls present outside of CMSSignedData.crls."));

                    arcTstV3Found = true;
                }
            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstV2Found);
        assertTrue(arcTstV3Found);
    }

    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isSigningCertificateIdentified());
        assertTrue(signature.isSigningCertificateReferencePresent());
        assertFalse(signature.isSigningCertificateReferenceUnique());
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertFalse(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

}