package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CAdESCounterSignSignaturesConsequentlyTest extends AbstractCAdESCounterSignatureTest {

    private final DSSDocument ORIGINAL_DOCUMENT = new InMemoryDocument("Hello World!".getBytes());

    private CAdESService service;
    private Date signingDate;

    private DSSDocument documentToSign;
    private String signingAlias;

    private CAdESSignatureParameters signatureParameters;
    private CAdESCounterSignatureParameters counterSignatureParameters;

    @BeforeEach
    public void init() throws Exception {
        service = new CAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = ORIGINAL_DOCUMENT;
        signingDate = new Date();

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

        counterSignatureParameters = new CAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(signingDate);
        counterSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        return signatureParameters;
    }

    @Override
    protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
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

        String signatureIdToCounterSign = null;
        for (AdvancedSignature signature : signatures) {
            if (!signature.isCounterSignature() && Utils.isCollectionEmpty(signature.getCounterSignatures())) {
                signatureIdToCounterSign = signature.getId();
                break;
            }
        }
        assertNotNull(signatureIdToCounterSign);

        signingAlias = SELF_SIGNED_USER;
        return super.counterSign(counterSigned, signatureIdToCounterSign);
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
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<CAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
