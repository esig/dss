package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class XAdESLevelLTWithCANoCrlSignTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private CertificateVerifier certificateVerifier;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        certificateVerifier = getCompleteCertificateVerifier();

        service = new XAdESService(certificateVerifier);
        service.setTspSource(getAlternateGoodTsa());
    }

    @Test
    @Override
    public void signAndVerify() {
        Exception exception = assertThrows(AlertException.class, super::signAndVerify);
        assertEquals(String.format("Revocation data is missing for one or more certificate(s). " +
                "[%s: No revocation data found for certificate!]", getSigningCert().getDSSIdAsString()), exception.getMessage());

        certificateVerifier.setRevocationFallback(true); // to accept invalid CRL

        super.signAndVerify();
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanCertificateObjects()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanCertificateReferences()));
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanRevocationObjects()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected String getSigningAlias() {
        return "ocsp-skip-ca-no-crl-sign-user";
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}
