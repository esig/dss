package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

// See DSS-3812
@Tag("slow")
class XAdESDoubleLTRevocationNoCacheTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(new MockPKICRLSource(getCertEntityRepository()));
        certificateVerifier.setOcspSource(pkiOCSPSource());
        service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @RepeatedTest(10)
    @Override
    public void signAndVerify() {
        super.signAndVerify();
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        assertEquals(2, diagnosticData.getAllRevocationData().size());
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
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
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    private class MockPKICRLSource extends PKICRLSource {

        private int callsCounter = 0;

        public MockPKICRLSource(CertEntityRepository<? extends CertEntity> certEntityRepository) {
            super(certEntityRepository);
        }

        @Override
        protected Date getThisUpdate() {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(signatureParameters.bLevel().getSigningDate());
            calendar.add(Calendar.SECOND, callsCounter);
            return calendar.getTime();
        }

        @Override
        public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
            ++callsCounter;
            return super.getRevocationToken(certificateToken, issuerCertificateToken);
        }

    }

}