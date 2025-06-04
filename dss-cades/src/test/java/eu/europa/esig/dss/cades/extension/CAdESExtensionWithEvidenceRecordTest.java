package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESExtensionWithEvidenceRecordTest extends AbstractCAdESTestExtension {

    private SignatureLevel finalSignatureLevel;

    private CertificateVerifier certificateVerifier;

    private Date extensionTime;

    @BeforeEach
    void init() {
        certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());

        extensionTime = DSSUtils.parseRFCDate("2024-01-01T00:00:00Z");
    }

    @Test
    void bLevelWithERExtensionTest() throws Exception {
        DSSDocument signedDocument = new InMemoryDocument(CAdESExtensionWithEvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/C-E-ERS-basic.p7m"));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LT;
        exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
        exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;
        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument tLevelSignature = extendSignature(signedDocument);
        Reports reports = verify(tLevelSignature);
        SignatureWrapper signature = reports.getDiagnosticData().getSignatureById(reports.getDiagnosticData().getFirstSignatureId());
        assertEquals(1, signature.getEvidenceRecords().size());
        assertEquals(1, signature.getTimestampList().size());
        assertEquals(1, signature.foundCertificates().getRelatedCertificates().size());

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LT;
        exception = assertThrows(AlertException.class, () -> extendSignature(tLevelSignature));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
        exception = assertThrows(AlertException.class, () -> extendSignature(tLevelSignature));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LT;
        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument ltLevelSignature = extendSignature(tLevelSignature);
        reports = verify(ltLevelSignature);
        signature = reports.getDiagnosticData().getSignatureById(reports.getDiagnosticData().getFirstSignatureId());
        assertEquals(1, signature.getEvidenceRecords().size());
        assertEquals(1, signature.getTimestampList().size());
        assertEquals(2, signature.foundCertificates().getRelatedCertificates().size());

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
        exception = assertThrows(AlertException.class, () -> extendSignature(ltLevelSignature));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument ltaLevelSignature = extendSignature(ltLevelSignature);
        reports = verify(ltaLevelSignature);
        signature = reports.getDiagnosticData().getSignatureById(reports.getDiagnosticData().getFirstSignatureId());
        assertEquals(1, signature.getEvidenceRecords().size());
        assertEquals(2, signature.getTimestampList().size());
        assertEquals(2, signature.foundCertificates().getRelatedCertificates().size());

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());
        exception = assertThrows(AlertException.class, () -> extendSignature(ltaLevelSignature));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument doubleLTALevelSignature = extendSignature(ltaLevelSignature);
        reports = verify(doubleLTALevelSignature);
        signature = reports.getDiagnosticData().getSignatureById(reports.getDiagnosticData().getFirstSignatureId());
        assertEquals(1, signature.getEvidenceRecords().size());
        assertEquals(3, signature.getTimestampList().size());
        assertEquals(2, signature.foundCertificates().getRelatedCertificates().size());
    }

    @Test
    void ersLevelWithERExtensionTest() throws Exception {
        DSSDocument signedDocument = new InMemoryDocument(CAdESExtensionWithEvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/C-E-ERS.p7m"));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("The signature is preserved by an embedded evidence record."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument ltaLevelSignature = extendSignature(signedDocument);
        Reports reports = verify(ltaLevelSignature);
        SignatureWrapper signature = reports.getDiagnosticData().getSignatureById(reports.getDiagnosticData().getFirstSignatureId());
        assertEquals(1, signature.getEvidenceRecords().size());
        assertEquals(2, signature.getTimestampList().size());
        assertEquals(5, signature.foundCertificates().getRelatedCertificates().size());
    }

    protected CertificateVerifier getCertificateVerifier() {
        return certificateVerifier;
    }

    @Override
    protected CAdESSignatureParameters getExtensionParameters() {
        CAdESSignatureParameters parameters = super.getExtensionParameters();
        parameters.bLevel().setSigningDate(extensionTime);
        return parameters;
    }

    @Override
    protected CAdESService getSignatureServiceToExtend() {
        CAdESService service = new CAdESService(getCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
        return service;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtExtensionTime() {
        return getKeyStoreTSPSourceByNameAndTime(SELF_SIGNED_LONG_TSA, extensionTime);
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return finalSignatureLevel;
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    public void extendAndVerify() throws Exception {
        // do nothing
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        // skip
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        // not valid
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        // out of scope
    }

    @Override
    protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
        // out of scope
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());

            List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
            for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
                if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != xmlDigestMatcher.getType()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                } else {
                    assertFalse(xmlDigestMatcher.isDataFound());
                    assertFalse(xmlDigestMatcher.isDataIntact());
                }
            }
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertNotNull(timestampWrapper.getArchiveTimestampType());
            }

            assertTrue(timestampWrapper.isSigningCertificateIdentified());
            assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
        }
    }

}
