package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class PAdESLevelBSha3AndEdDSAPdf20DeveloperExtensionTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdf-2.0.pdf"));
        signingAlias = RSA_SHA3_USER;

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA3_256);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        signingAlias = ED25519_GOOD_USER;
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

        documentToSign = signedDocument;
        return super.sign();
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        DSSDocument signedDocument = new InMemoryDocument(byteArray);
        try {
            PdfDocumentReader documentReader = getDocumentReader(signedDocument);
            PdfDict catalogDictionary = documentReader.getCatalogDictionary();
            PdfDict extensionsDict = catalogDictionary.getAsDict("Extensions");
            assertNotNull(extensionsDict);
            PdfDict adbeDict = extensionsDict.getAsDict("ADBE");
            assertNull(adbeDict); // PDF 2.0 already defines the extensions
            PdfArray isoArray = extensionsDict.getAsArray("ISO_");
            assertNotNull(isoArray);
            assertEquals(2, isoArray.size());
            PdfDict iso32001Dict = isoArray.getAsDict(0);
            assertEquals("2.0", iso32001Dict.getNameValue("BaseVersion"));
            assertEquals(32001, iso32001Dict.getNumberValue("ExtensionLevel").intValue());
            assertEquals(":2022", iso32001Dict.getStringValue("ExtensionRevision"));
            assertEquals("DeveloperExtensions", iso32001Dict.getNameValue("Type"));
            assertEquals("https://www.iso.org/standard/45874.html", iso32001Dict.getStringValue("URL"));
            PdfDict iso32002Dict = isoArray.getAsDict(1);
            assertEquals("2.0", iso32002Dict.getNameValue("BaseVersion"));
            assertEquals(32002, iso32002Dict.getNumberValue("ExtensionLevel").intValue());
            assertEquals(":2022", iso32002Dict.getStringValue("ExtensionRevision"));
            assertEquals("DeveloperExtensions", iso32002Dict.getNameValue("Type"));
            assertEquals("https://www.iso.org/standard/45875.html", iso32002Dict.getStringValue("URL"));
        } catch (IOException e) {
            fail(e);
        }
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
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
    protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    protected abstract PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException;

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
        return signingAlias;
    }

}
