package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CAdESWithPSSTest extends AbstractCAdESTestSignature {

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument("Hello World".getBytes());

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        service = new CAdESService(getCertificateVerifierWithPSS());
        service.setTspSource(getPSSGoodTsa());
    }

    @Override
    protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
        super.verifyDiagnosticData(diagnosticData);

        Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
        for (SignatureWrapper wrapper: allSignatures) {
            assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
        }

        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        for (CertificateWrapper wrapper: usedCertificates) {
            assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
        }

        Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
        for (RevocationWrapper wrapper : allRevocationData) {
            assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
        }

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper wrapper : timestampList) {
            assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
        }
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return RSASSA_PSS_GOOD_USER;
    }

}