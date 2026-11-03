package eu.europa.esig.dss.cbades.signature;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.COSEDocumentAnalyzer;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CertificateThumbprints;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBIncludeNoCertThumbprintsTest extends AbstractCBAdESTestSignature {

    private CBAdESService service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getCompleteCertificateVerifier());
        documentToSign = new InMemoryDocument("Hello world!".getBytes());
        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setCertificateThumbprints(CertificateThumbprints.NONE);
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        COSEDocumentAnalyzer analyzer = new COSEDocumentAnalyzer(new InMemoryDocument(byteArray));
        List<AdvancedSignature> signatures = analyzer.getSignatures();
        assertEquals(1, signatures.size());

        CBAdESSignature signature = (CBAdESSignature) signatures.get(0);
        COSEProtectedHeader protectedHeader = signature.getCoseSignature().getBodyProtectedHeader();
        assertNotNull(protectedHeader);

        CBORValue x5t = protectedHeader.getHeader(COSEHeaderParameter.X5T.cbor());
        assertNull(x5t);

        CBORValue x5ts = protectedHeader.getHeader(COSEHeaderParameter.X5TS.cbor());
        assertNull(x5ts);

        CBORValue x5chain = protectedHeader.getHeader(COSEHeaderParameter.X5CHAIN.cbor());
        assertNotNull(x5chain);
        assertTrue(x5chain.isArray());
        assertEquals(2, x5chain.size());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        assertFalse(signature.isSigningCertificateIdentified());
        assertFalse(signature.isSigningCertificateReferencePresent());

        CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
        assertNull(signingCertificateReference);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        assertNotNull(signingCertificate);
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected CBAdESService getService() {
        return service;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return PKIFactoryAccess.GOOD_USER;
    }

}
