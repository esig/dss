package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XAdESLevelTWithTSVDValidationTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/xades-t-with-tsvd.xml"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);
        assertEquals(SignatureLevel.XAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        super.checkCertificates(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(
                CertificateOrigin.CERTIFICATE_VALUES).size());
        assertEquals(2, signature.foundCertificates().getRelatedCertificatesByOrigin(
                CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(
                RevocationOrigin.REVOCATION_VALUES).size());
        assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(
                RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
    }

}
