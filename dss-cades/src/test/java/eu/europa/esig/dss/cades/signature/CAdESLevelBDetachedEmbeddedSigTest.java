package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBDetachedEmbeddedSigTest extends AbstractCAdESTestSignature {

    private static DSSDocument originalDocument;

    private DSSDocument documentToSign;
    private CAdESSignatureParameters parameters;
    private CAdESService service;

    @BeforeEach
    void init() {
        originalDocument = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8));
        documentToSign = originalDocument;

        parameters = new CAdESSignatureParameters();
        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        parameters.setSigningCertificate(getSigningCert());
        parameters.setCertificateChain(getCertificateChain());
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setParallelSignature(false);

        service = new CAdESService(getOfflineCertificateVerifier());
    }

    @Test
    @Override
    public void signAndVerify() {
        DSSDocument signed = sign();

        CMSSignedData signedCMS = DSSUtils.toCMSSignedData(signed);
        assertTrue(signedCMS.isDetachedSignature());

        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        documentToSign = signed;

        DSSDocument doubleSigned = sign();
        CMSSignedData doubleSignedCMS = DSSUtils.toCMSSignedData(doubleSigned);
        assertFalse(doubleSignedCMS.isDetachedSignature());

        verify(doubleSigned);

        DSSDocument secondSignedDocument = CMSUtils.getOriginalDocument(doubleSignedCMS, getDetachedContents());
        secondSignedDocument.setName("secondSignedDocument.p7s");
        signedCMS = DSSUtils.toCMSSignedData(secondSignedDocument);
        assertTrue(signedCMS.isDetachedSignature());

        documentToSign = originalDocument;

        verify(secondSignedDocument);

        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        documentToSign = signed;

        doubleSigned = sign();
        doubleSignedCMS = DSSUtils.toCMSSignedData(doubleSigned);
        assertTrue(doubleSignedCMS.isDetachedSignature());

        verify(doubleSigned);

        secondSignedDocument = CMSUtils.getOriginalDocument(doubleSignedCMS, getDetachedContents());
        signedCMS = DSSUtils.toCMSSignedData(secondSignedDocument);
        assertTrue(signedCMS.isDetachedSignature());

        documentToSign = originalDocument;

        verify(secondSignedDocument);
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(documentToSign);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return parameters;
    }

}
