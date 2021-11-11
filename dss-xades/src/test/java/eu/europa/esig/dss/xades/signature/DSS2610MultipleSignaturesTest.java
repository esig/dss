package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/*
 * In this unit test a revocation data shall be requested for the second signature on validation
 */
public class DSS2610MultipleSignaturesTest extends AbstractXAdESTestSignature {

    private static final DSSDocument ORIGINAL_DOC = new FileDocument("src/test/resources/sample.xml");

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private Date signingTime;

    private MockOnlineCRLSource mockOnlineCRLSource;

    @BeforeEach
    public void init() throws Exception {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MONTH, -1);
        signingTime = calendar.getTime();

        signatureParameters = initSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        signatureParameters.bLevel().setSigningDate(signingTime);

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsaByTime(signingTime));

        mockOnlineCRLSource = new MockOnlineCRLSource();
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = ORIGINAL_DOC;
        DSSDocument signedDocument = super.sign();

        documentToSign = signedDocument;
        signatureParameters = initSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.bLevel().setSigningDate(new Date());
        DSSDocument doubleSignedDoc = super.sign();

        documentToSign = ORIGINAL_DOC;
        return doubleSignedDoc;
    }

    private XAdESSignatureParameters initSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        return signatureParameters;
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
        assertEquals(1, mockOnlineCRLSource.requestCounter);
        return verify;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean bLevelSigFound = false;
        boolean ltLevelSigFound = false;
        for (String sigId : diagnosticData.getSignatureIdList()) {
            if (SignatureLevel.XAdES_BASELINE_B.equals(diagnosticData.getSignatureFormat(sigId))) {
                bLevelSigFound = true;
            } else if (SignatureLevel.XAdES_BASELINE_LT.equals(diagnosticData.getSignatureFormat(sigId))) {
                ltLevelSigFound = true;
            }
        }
        assertTrue(bLevelSigFound);
        assertTrue(ltLevelSigFound);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
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
