package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class XAdESLevelBCrossCertificationWithAltTrustAnchorTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER_CROSS_CERTIF;
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(getCertificateByPrimaryKey(2004, "cc-root-ca-alt"));
        return trustedCertificateSource;
    }

    @Override
    protected void checkCertificateChain(DiagnosticData diagnosticData) {
        List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChainIds(diagnosticData.getFirstSignatureId());
        assertEquals(5, signatureCertificateChain.size());

        boolean trustedCertFound = false;
        for (String certId : signatureCertificateChain) {
            CertificateWrapper certificate = diagnosticData.getCertificateById(certId);
            if (certificate.isTrusted()) {
                trustedCertFound = true;
                break;
            }
        }
        assertFalse(trustedCertFound);
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
