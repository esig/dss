package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.cbades.validation.AbstractCBAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESCoseSign1NestedCounterSignatureTest extends AbstractCBAdESTestValidation {

    private CBAdESService service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;
    private CBAdESCounterSignatureParameters counterSignatureParameters;

    @BeforeEach
    void init() {
        documentToSign = new InMemoryDocument("Hello world!".getBytes());

        service = new CBAdESService(getCompleteCertificateVerifier());

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);

        counterSignatureParameters = new CBAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(new Date());
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
    }

    @Test
    void test() throws Exception {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters));
        assertEquals("The Id of a signature to be counter signed shall be defined! "
                + "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.", exception.getMessage());

        SignedDocumentValidator validator = getValidator(signedDocument);
        counterSignatureParameters.setSignatureIdToCounterSign(validator.getSignatures().get(0).getId());

        ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
        signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument counterSignedSignature = service.counterSignSignature(signedDocument, counterSignatureParameters, signatureValue);

        // counterSignedSignature.save("target/counterSignedSignature.cose");
        verify(counterSignedSignature);

        validator = getValidator(counterSignedSignature);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        AdvancedSignature advancedSignature = signatures.get(0);
        List<AdvancedSignature> counterSignatures = advancedSignature.getCounterSignatures();
        assertEquals(1, counterSignatures.size());

        AdvancedSignature counterSignature = counterSignatures.get(0);
        assertNotNull(counterSignature.getMasterSignature());
        assertEquals(0, counterSignature.getCounterSignatures().size());

        counterSignatureParameters.bLevel().setSigningDate(new Date());
        counterSignatureParameters.setSignatureIdToCounterSign(counterSignature.getId());

        dataToBeCounterSigned = service.getDataToBeCounterSigned(counterSignedSignature, counterSignatureParameters);
        signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument nestedCounterSignedSignature = service.counterSignSignature(counterSignedSignature, counterSignatureParameters, signatureValue);

        // nestedCounterSignedSignature.save("target/nestedCounterSignature.cose");

        validator = getValidator(nestedCounterSignedSignature);

        signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        advancedSignature = signatures.get(0);
        counterSignatures = advancedSignature.getCounterSignatures();
        assertEquals(1, counterSignatures.size());

        counterSignature = counterSignatures.get(0);
        assertNotNull(counterSignature.getMasterSignature());
        assertEquals(1, counterSignature.getCounterSignatures().size());

        Reports reports = verify(nestedCounterSignedSignature);
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
        assertEquals(3, signatureWrappers.size());

        boolean rootSignatureFound = false;
        boolean counterSignatureFound = false;
        boolean nestedCounterSignatureFound = false;
        for (SignatureWrapper signatureWrapper : signatureWrappers) {
            if (!signatureWrapper.isCounterSignature()) {
                assertEquals(COSESignatureType.COSE_SIGN1, signatureWrapper.getCOSESignatureType());
                rootSignatureFound = true;
            } else if (signatureWrapper.getParent() != null && signatureWrapper.getParent().getParent() == null) {
                assertEquals(COSESignatureType.COSE_COUNTER_SIGNATURE_V2, signatureWrapper.getCOSESignatureType());
                counterSignatureFound = true;
            } else if (signatureWrapper.getParent() != null && signatureWrapper.getParent().getParent() != null) {
                assertEquals(COSESignatureType.COSE_COUNTER_SIGNATURE, signatureWrapper.getCOSESignatureType());
                nestedCounterSignatureFound = true;
            }
        }
        assertTrue(rootSignatureFound);
        assertTrue(counterSignatureFound);
        assertTrue(nestedCounterSignatureFound);
    }

    @Override
    public void validate() {
        // do nothing
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
