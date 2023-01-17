package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESDoubleSignatureLTAndLTWithVRITest extends AbstractPAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private Date signingTime;

    @BeforeEach
    public void init() throws Exception {
        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        originalDocument = new InMemoryDocument(PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

        signingTime = new Date();
    }

    @Override
    protected DSSDocument sign() {
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        signatureParameters.setIncludeVRIDictionary(false);

        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        signatureParameters.setIncludeVRIDictionary(true);

        documentToSign = signedDocument;
        return super.sign();
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        for (AdvancedSignature signature : signatures) {
            PAdESSignature padesSignature = (PAdESSignature) signature;

            PdfDssDict dssDictionary = padesSignature.getDssDictionary();
            assertNotNull(dssDictionary);

            assertTrue(Utils.isMapNotEmpty(dssDictionary.getCERTs()));
            assertTrue(Utils.isMapNotEmpty(dssDictionary.getCRLs()));
            assertTrue(Utils.isMapNotEmpty(dssDictionary.getOCSPs()));
            assertTrue(Utils.isCollectionNotEmpty(dssDictionary.getVRIs()));
            assertEquals(2, dssDictionary.getVRIs().size());

            boolean vriFound = false;
            for (PdfVriDict vriDict : dssDictionary.getVRIs()) {
                if (padesSignature.getVRIKey().equals(vriDict.getName())) {
                    assertTrue(Utils.isMapNotEmpty(vriDict.getCERTs()));
                    assertTrue(Utils.isMapNotEmpty(vriDict.getCRLs()));
                    assertTrue(Utils.isMapNotEmpty(vriDict.getOCSPs()));
                    vriFound = true;
                }
            }
            assertTrue(vriFound);
        }
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
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
        signatureParameters.bLevel().setSigningDate(signingTime);
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
