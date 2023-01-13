package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
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
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESLevelLTWithVRIDictTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        signatureParameters.setIncludeVRIDictionary(true);

        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        PAdESSignature padesSignature = (PAdESSignature) signatures.get(0);

        PdfDssDict dssDictionary = padesSignature.getDssDictionary();
        assertNotNull(dssDictionary);

        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCERTs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCRLs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getOCSPs()));
        assertTrue(Utils.isCollectionNotEmpty(dssDictionary.getVRIs()));

        assertEquals(1, dssDictionary.getVRIs().size());
        PdfVriDict pdfVriDict = dssDictionary.getVRIs().get(0);
        assertTrue(Utils.isMapNotEmpty(pdfVriDict.getCERTs()));
        assertTrue(Utils.isMapNotEmpty(pdfVriDict.getCRLs()));
        assertTrue(Utils.isMapNotEmpty(pdfVriDict.getOCSPs()));
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
