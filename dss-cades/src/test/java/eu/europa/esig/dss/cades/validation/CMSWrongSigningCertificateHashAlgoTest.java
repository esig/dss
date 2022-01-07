package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CMSWrongSigningCertificateHashAlgoTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cms-wrong-sign-cert-hash-algo.pkcs7");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // signing-certificate attribute shall be used with SHA-1
        assertEquals(SignatureLevel.CMS_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}