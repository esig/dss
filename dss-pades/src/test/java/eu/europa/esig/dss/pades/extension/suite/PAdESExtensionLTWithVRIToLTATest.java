package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExtensionLTWithVRIToLTATest extends PAdESExtensionLTToLTATest {

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        PAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setIncludeVRIDictionary(true);
        return signatureParameters;
    }

    @Override
    protected PAdESSignatureParameters getExtensionParameters() {
        PAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setIncludeVRIDictionary(false);
        return extensionParameters;
    }

    @Override
    protected void onDocumentSigned(DSSDocument signedDocument) {
        super.onDocumentSigned(signedDocument);

        PDFDocumentValidator documentValidator = new PDFDocumentValidator(signedDocument);

        List<AdvancedSignature> signatures = documentValidator.getSignatures();
        assertEquals(1, signatures.size());

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
    protected void onDocumentExtended(DSSDocument extendedDocument) {
        super.onDocumentExtended(extendedDocument);

        PDFDocumentValidator documentValidator = new PDFDocumentValidator(extendedDocument);

        List<AdvancedSignature> signatures = documentValidator.getSignatures();
        assertEquals(1, signatures.size());

        PAdESSignature padesSignature = (PAdESSignature) signatures.get(0);

        PdfDssDict dssDictionary = padesSignature.getDssDictionary();
        assertNotNull(dssDictionary);

        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCERTs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCRLs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getOCSPs()));
        assertFalse(Utils.isCollectionNotEmpty(dssDictionary.getVRIs()));
    }

}
