package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JAdESDoubleSignBAndExtendToLTATest extends AbstractJAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private JAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        originalDocument = new FileDocument(new File("src/test/resources/sample.json"));
    }

    @Override
    protected DSSDocument sign() {
        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        documentToSign = signedDocument;
        DSSDocument doubleSignedDocument = super.sign();

        JAdESSignatureParameters extensionParameters = new JAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        extensionParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        DSSDocument extendedDocument = service.extendDocument(doubleSignedDocument, extensionParameters);

        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        documentToSign = originalDocument;
        return extendedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        // skip
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.JAdES_BASELINE_LTA, signature.getSignatureFormat());
        }
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
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
