package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBNestedSignatureTest extends AbstractCAdESTestSignature {

    private static DSSDocument originalDocument;
    private static Date date;

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeAll
    static void initBeforeAll() {
        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        date = new Date();
    }

    @BeforeEach
    void init() throws Exception {
        documentToSign = originalDocument;

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(date);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setParallelSignature(false);

        service = new CAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();
        documentToSign = signedDocument;
        DSSDocument nestedSignatureDocument = super.sign();
        return nestedSignatureDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(1, diagnosticData.getSignatures().size());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        super.verifyOriginalDocuments(validator, diagnosticData);

        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        assertEquals(1, originalDocuments.size());

        DSSDocument nestedSignatureDocument = originalDocuments.get(0);
        CMSDocumentValidator cmsDocumentValidator = new CMSDocumentValidator(nestedSignatureDocument);
        cmsDocumentValidator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports = cmsDocumentValidator.validateDocument();
        diagnosticData = reports.getDiagnosticData();

        assertEquals(1, diagnosticData.getSignatures().size());
        assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

        originalDocuments = cmsDocumentValidator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        assertEquals(1, originalDocuments.size());
        assertArrayEquals(DSSUtils.toByteArray(originalDocument), DSSUtils.toByteArray(originalDocuments.get(0)));
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
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
