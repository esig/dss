package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JAdESCounterSignSignaturesConsequentlyTest extends AbstractJAdESCounterSignatureTest {

    private final DSSDocument ORIGINAL_DOCUMENT = new FileDocument("src/test/resources/sample.json");

    private JAdESService service;
    private Date signingDate;

    private DSSDocument documentToSign;
    private String signingAlias;

    private JAdESSignatureParameters signatureParameters;
    private JAdESCounterSignatureParameters counterSignatureParameters;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = ORIGINAL_DOCUMENT;
        signingDate = new Date();

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);

        counterSignatureParameters = new JAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(signingDate);
        counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        return signatureParameters;
    }

    @Override
    protected JAdESCounterSignatureParameters getCounterSignatureParameters() {
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = GOOD_USER;

        DSSDocument signedDocument = super.sign();

        documentToSign = signedDocument;
        signingAlias = EE_GOOD_USER;

        DSSDocument doubleSignedDocument = super.sign();

        documentToSign = ORIGINAL_DOCUMENT;

        return doubleSignedDocument;
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        SignedDocumentValidator validator = getValidator(signatureDocument);
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(2, signatures.size());

        signingAlias = RSA_SHA3_USER;
        DSSDocument counterSigned = super.counterSign(signatureDocument, signatures.get(0).getId());

        validator = getValidator(counterSigned);
        signatures = validator.getSignatures();
        assertEquals(2, signatures.size());

        signingAlias = SELF_SIGNED_USER;
        return super.counterSign(counterSigned, signatures.get(1).getId());
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(4, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertEquals(2, signatures.size());

        for (AdvancedSignature signature : signatures) {
            List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
            assertEquals(1, counterSignatures.size());
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip (different signers)
    }

    @Override
    protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip (different signers)
    }

    @Override
    protected void checkCertificateChain(DiagnosticData diagnosticData) {
        // skip (different signers)
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip (different signers)
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<JAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
