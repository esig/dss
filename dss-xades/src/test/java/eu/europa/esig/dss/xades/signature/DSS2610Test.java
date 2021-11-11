package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/*
 * In this unit test no revocation data shall be requested on validation
 */
public class DSS2610Test extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private MockOnlineCRLSource mockOnlineCRLSource;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MONTH, -1);
        Date signingTime = calendar.getTime();

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsaByTime(signingTime));

        mockOnlineCRLSource = new MockOnlineCRLSource();
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(mockOnlineCRLSource);
        validator.setCertificateVerifier(certificateVerifier);

        return validator;
    }

    @Override
    protected Reports verify(DSSDocument signedDocument) {
        Reports verify = super.verify(signedDocument);

        assertEquals(0, mockOnlineCRLSource.requestCounter);

        return verify;
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        int externalRevocationDataCounter = 0;
        Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
        for (RevocationWrapper revocationWrapper : allRevocationData) {
            if (RevocationOrigin.EXTERNAL.equals(revocationWrapper.getOrigin())) {
                ++externalRevocationDataCounter;
            }
        }
        assertEquals(0, externalRevocationDataCounter);
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

    private class MockOnlineCRLSource extends OnlineCRLSource {

        private int requestCounter = 0;

        @Override
        public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
            ++requestCounter;
            return super.getRevocationToken(certificateToken, issuerCertificateToken);
        }
    }

}
