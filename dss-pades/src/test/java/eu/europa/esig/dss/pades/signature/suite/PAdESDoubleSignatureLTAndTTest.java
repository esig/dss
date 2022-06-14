package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-2761
public class PAdESDoubleSignatureLTAndTTest extends AbstractPAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new PAdESService(getCompleteCertificateVerifier());

        Calendar firstTSATime = Calendar.getInstance();
        firstTSATime.add(Calendar.HOUR, -1);
        service.setTspSource(getGoodTsaByTime(firstTSATime.getTime()));

        originalDocument = new InMemoryDocument(PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));
    }

    @Override
    protected DSSDocument sign() {
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        PAdESSignatureParameters extensionParameters = new PAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extensionParameters);

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        Calendar secondTSATime = Calendar.getInstance();
        secondTSATime.add(Calendar.HOUR, 1);
        service.setTspSource(getGoodTsaByTime(secondTSATime.getTime()));

        service.setTspSource(getGoodTsa());
        documentToSign = extendedDocument;
        DSSDocument doubleSignedDocument = super.sign();

        // Ensure revocation update
        Calendar nextSecond = Calendar.getInstance();
        nextSecond.add(Calendar.SECOND, 1);
        await().atMost(2, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().compareTo(nextSecond.getTime()) > 0);

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        documentToSign = originalDocument;
        return doubleSignedDocument;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        // to no cache
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();

        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(2, certificateRevocationData.size());

        boolean documentRevocationFound = false;
        boolean externalRevocationFound = false;
        for (RevocationWrapper revocationWrapper : certificateRevocationData) {
            assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
            if (revocationWrapper.getOrigin().isInternalOrigin()) {
                documentRevocationFound = true;
            } else {
                externalRevocationFound = true;
            }
        }
        assertTrue(documentRevocationFound);
        assertTrue(externalRevocationFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(2, timestampList.size());

        boolean docTstFound = false;
        boolean sigTstFound = false;
        for (TimestampWrapper timestamp : timestampList) {
            if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestamp.getType())) {
                assertEquals(1, timestamp.getTimestampedSignatures().size());
                assertEquals(0, timestamp.getTimestampedTimestamps().size());
                docTstFound = true;
            } else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
                assertEquals(1, timestamp.getTimestampedSignatures().size());
                assertEquals(0, timestamp.getTimestampedTimestamps().size());
                sigTstFound = true;
            }
        }
        assertTrue(docTstFound);
        assertTrue(sigTstFound);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}