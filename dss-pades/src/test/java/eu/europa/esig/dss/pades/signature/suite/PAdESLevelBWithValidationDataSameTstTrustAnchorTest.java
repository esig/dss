package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESLevelBWithValidationDataSameTstTrustAnchorTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getCompleteCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        PDFSignatureService pdfSignatureService = new ServiceLoaderPdfObjFactory().newPAdESSignatureService();

        PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(signedDocument);
        pdfDocumentValidator.setCertificateVerifier(getCompleteCertificateVerifier());
        PdfValidationDataContainer validationData = pdfDocumentValidator.getValidationData(pdfDocumentValidator.getSignatures(), Collections.emptyList());

        signedDocument = pdfSignatureService.addDssDictionary(signedDocument, validationData);

        signedDocument.setName("signed.pdf");
        signedDocument.setMimeType(MimeType.PDF);
        return signedDocument;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        DSSDocument signedDocument = new InMemoryDocument(byteArray);

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        service.setTspSource(getGoodTsa());

        DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
        SignedDocumentValidator validator = getValidator(extendedDocument);
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());
        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signatures.get(0).getDataFoundUpToLevel());

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

        extendedDocument = service.extendDocument(signedDocument, signatureParameters);
        validator = getValidator(extendedDocument);
        signatures = validator.getSignatures();
        assertEquals(1, signatures.size());
        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signatures.get(0).getDataFoundUpToLevel());

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        extendedDocument = service.extendDocument(signedDocument, signatureParameters);
        validator = getValidator(extendedDocument);
        signatures = validator.getSignatures();
        assertEquals(1, signatures.size());
        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signatures.get(0).getDataFoundUpToLevel());
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(Utils.isCollectionNotEmpty(signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.DSS_DICTIONARY)));
        assertTrue(Utils.isCollectionNotEmpty(signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.VRI_DICTIONARY)));
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertNotNull(signatureScopes);
        assertEquals(1, signatureScopes.size());
        XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
        assertEquals(SignatureScopeType.PARTIAL, xmlSignatureScope.getScope());
    }

    @Override
    protected void validateETSIDSSType(SADSSType dss) {
        assertNotNull(dss);
    }

    @Override
    protected void validateETSIVRIType(SAVRIType vri) {
        assertNotNull(vri);
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