package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.CertificationPermission;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PAdESLevelBWithNoChangesPermittedTest extends AbstractPAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        originalDocument = new InMemoryDocument(PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setPermission(CertificationPermission.NO_CHANGE_PERMITTED);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        documentToSign = signedDocument;
        Exception exception = assertThrows(AlertException.class, () -> super.sign());
        assertEquals("The creation of new signatures is not permitted in the current document.", exception.getMessage());

        documentToSign = originalDocument;
        return signedDocument;
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());

        SignatureWrapper signatureWrapper = signatures.get(0);
        XmlPDFRevision pdfRevision = signatureWrapper.getPDFRevision();
        assertNotNull(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = pdfRevision.getPDFSignatureDictionary();
        assertNotNull(pdfSignatureDictionary);

        XmlDocMDP docMDP = pdfSignatureDictionary.getDocMDP();
        assertNotNull(docMDP);
        assertEquals(1, docMDP.getPermissions().intValue());
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
