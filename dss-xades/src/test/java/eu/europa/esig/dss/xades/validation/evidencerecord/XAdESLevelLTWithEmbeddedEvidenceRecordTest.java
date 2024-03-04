package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelLTWithEmbeddedEvidenceRecordTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-LT.xml");
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        // skip (time-stamp has two signing-certificate attributes)
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        // does not allow other namespaces ?
    }

}
