package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESTripleSignatureWithUserFriendlyIdentifierTest extends AbstractXAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private Date signingTime = new Date();

    @BeforeEach
    public void init() throws Exception {
        originalDocument = new FileDocument(new File("src/test/resources/sample.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
        String timeString = sdf.format(signingTime);
        signingTime = sdf.parse(timeString); // remove millis
    }

    private XAdESSignatureParameters initSignatureParameters() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(signingTime);
        calendar.add(Calendar.MILLISECOND, 1);
        signingTime = calendar.getTime();

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        signatureParameters = initSignatureParameters();
        DSSDocument signed = super.sign();

        documentToSign = signed;
        signatureParameters = initSignatureParameters();

        DSSDocument doubleSigned = super.sign();

        documentToSign = doubleSigned;
        signatureParameters = initSignatureParameters();

        DSSDocument tripleSigned = super.sign();

        documentToSign = originalDocument;
        return tripleSigned;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setTokenIdentifierProvider(new UserFriendlyIdentifierProvider());
        return validator;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(3, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        super.checkSignatureIdentifier(diagnosticData);

        boolean firstSigFound = false;
        boolean secondSigFound = false;
        boolean thirdSigFound = false;
        for (String sigId : diagnosticData.getSignatureIdList()) {
            if (sigId.endsWith("_2")) {
                secondSigFound = true;
            } else if (sigId.endsWith("_3")) {
                thirdSigFound = true;
            } else {
                firstSigFound = true;
            }
        }
        assertTrue(firstSigFound);
        assertTrue(secondSigFound);
        assertTrue(thirdSigFound);
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
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
