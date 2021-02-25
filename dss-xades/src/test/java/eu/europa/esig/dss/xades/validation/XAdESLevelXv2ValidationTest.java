package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelXv2ValidationTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/xades-x-level-v2.xml"));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(2, timestampList.size());

        boolean sigTstFound = false;
        boolean sigAndRefsTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                sigTstFound = true;
            } else if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestampWrapper.getType())) {
                sigAndRefsTstFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(sigAndRefsTstFound);
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        assertEquals(4, foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size() +
                foundCertificates.getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());

        FoundRevocationsProxy foundRevocations = signature.foundRevocations();
        assertEquals(2, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size() +
                foundRevocations.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
        assertEquals(1, foundRevocations.getRelatedRevocationsByType(RevocationType.CRL).size() +
                foundRevocations.getOrphanRevocationsByType(RevocationType.CRL).size());
        assertEquals(1, foundRevocations.getRelatedRevocationsByType(RevocationType.OCSP).size() +
                foundRevocations.getOrphanRevocationsByType(RevocationType.OCSP).size());
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        // skip
    }
}
