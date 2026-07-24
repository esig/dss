package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocServiceTest extends PKIFactoryAccess {

    private MdocService service;
    private CBAdESSignatureParameters signatureParameters;
    private MdocPayloadParameters payloadParameters;

    @BeforeEach
    void init() {
        service = new MdocService(getOfflineCertificateVerifier());

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());
        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");
    }

    @Test
    void signEAAWithDSSDocumentTest() {
        DSSDocument cborPayload = new InMemoryDocument(CBORUtils.serializeCborObject(new CBORMap()), "payload.cbor");
        DSSDocument nonCborPayload = new InMemoryDocument("not-cbor-content".getBytes(), "payload.txt");
        CBAdESSignatureParameters params = new CBAdESSignatureParameters();
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);

        Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToBeSigned((DSSDocument) null, params));
        assertEquals("payload cannot be null!", exception.getMessage());

        exception = assertThrows(IllegalInputException.class, () -> service.getDataToBeSigned(nonCborPayload, params));
        assertEquals("Payload is not a CBOR document!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> service.getDataToBeSigned(cborPayload, null));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        params.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_T);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToBeSigned(cborPayload, params));
        assertEquals("Signature level must be CB-AdES-BASELINE-B!", exception.getMessage());
        params.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);

        params.setSignaturePackaging(SignaturePackaging.DETACHED);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToBeSigned(cborPayload, params));
        assertEquals("Signature packaging must be ENVELOPING", exception.getMessage());
        params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        params.setIncludeCertificateChain(false);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToBeSigned(cborPayload, params));
        assertEquals("Certificate chain must be included within the mdoc EAA signature!", exception.getMessage());
        params.setIncludeCertificateChain(true);

        params.setX5ChainHeaderPlacement(CBAdESSignatureParameters.X5ChainHeaderPlacement.protectedHeader);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToBeSigned(cborPayload, params));
        assertEquals("'x5chain' shall be placed within the unsigned header map! Obtained value : 'protectedHeader'", exception.getMessage());

        params.setX5ChainHeaderPlacement(null);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToBeSigned(cborPayload, params));
        assertEquals("MSO shall be signed by ECDSA or EDDSA algortihm! Obtained value : 'RSASSA_PSS'", exception.getMessage());

        params.setSigningCertificate(getSigningCert());
        params.setCertificateChain(getCertificateChain());

        params.setTagged(true);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToBeSigned(cborPayload, params));
        assertEquals("COSE_Sign1 structure shall be untagged!", exception.getMessage());

        params.setTagged(false);

        ToBeSigned dataToSign = service.getDataToBeSigned(cborPayload, params);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());

        exception = assertThrows(NullPointerException.class, () -> service.signEAA((DSSDocument) null, params, signatureValue));
        assertEquals("payload cannot be null!", exception.getMessage());

        exception = assertThrows(IllegalInputException.class, () -> service.signEAA(nonCborPayload, params, signatureValue));
        assertEquals("Payload is not a CBOR document!", exception.getMessage());

        DSSDocument signedEAA = service.signEAA(cborPayload, params, signatureValue);
        assertNotNull(signedEAA);
    }

    @Test
    void signEAAWithPayloadParametersTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToBeSigned((MdocPayloadParameters) null, signatureParameters));
        assertEquals("MdocEAAPayloadParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> service.getDataToBeSigned(payloadParameters, null));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        CBAdESSignatureParameters params = new CBAdESSignatureParameters();
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToBeSigned(payloadParameters, params));
        assertEquals("MSO shall be signed by ECDSA or EDDSA algortihm! Obtained value : 'RSASSA_PSS'", exception.getMessage());

        ToBeSigned dataToSign = service.getDataToBeSigned(payloadParameters, signatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());

        exception = assertThrows(NullPointerException.class, () -> service.signEAA((MdocPayloadParameters) null, signatureParameters, signatureValue));
        assertEquals("MdocEAAPayloadParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> service.signEAA(payloadParameters, null, signatureValue));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        DSSDocument signedEAA = service.signEAA(payloadParameters, signatureParameters, signatureValue);
        assertNotNull(signedEAA);
    }

    @Test
    void getDisclosuresTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> service.getDisclosures(null));
        assertEquals("MdocEAAPayloadParameters cannot be null!", exception.getMessage());

        MdocPayloadParameters params = new MdocPayloadParameters();

        exception = assertThrows(NullPointerException.class, () -> service.getDisclosures(params));
        assertEquals("Signed date cannot be null!", exception.getMessage());
        params.setSigned(new Date());

        exception = assertThrows(NullPointerException.class, () -> service.getDisclosures(params));
        assertEquals("ValidFrom date cannot be null!", exception.getMessage());
        params.setValidFrom(new Date());

        exception = assertThrows(NullPointerException.class, () -> service.getDisclosures(params));
        assertEquals("ValidUntil date cannot be null!", exception.getMessage());
        params.setValidUntil(new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000));

        exception = assertThrows(NullPointerException.class, () -> service.getDisclosures(params));
        assertEquals("DocType cannot be null!", exception.getMessage());
        params.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);

        List<MdocSelectiveDisclosure> disclosures = service.getDisclosures(params);
        assertNotNull(disclosures);
        assertTrue(disclosures.isEmpty());

        params.selectivelyDisclosable().setGivenName("John");
        params.selectivelyDisclosable().setFamilyName("Doe");
        disclosures = service.getDisclosures(params);
        assertNotNull(disclosures);
        assertEquals(2, disclosures.size());
        for (MdocSelectiveDisclosure disclosure : disclosures) {
            assertNotNull(disclosure.getNamespace());
            assertNotNull(disclosure.getIssuerSignedItemBytes());
        }
    }

    @Test
    void keyBindingSignatureTest() {
        DSSDocument signedEAA = createSignedEAA(payloadParameters, signatureParameters);

        MdocKeyBindingParameters keyBindingParameters = new MdocKeyBindingParameters();
        CBAdESSignatureParameters kbSignParams = new CBAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, null));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        kbSignParams.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_T);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("Signature level must be CB-AdES-BASELINE-B!", exception.getMessage());
        kbSignParams.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);

        kbSignParams.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("Signature packaging must be DETACHED!", exception.getMessage());
        kbSignParams.setSignaturePackaging(SignaturePackaging.DETACHED);

        kbSignParams.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("SigDMechanism must be NO_SIG_D!", exception.getMessage());
        kbSignParams.setSigDMechanism(SigDMechanism.NO_SIG_D);

        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("DeviceAuthentication shall be signed by ECDSA or EDDSA algortihm! Obtained value : 'RSASSA_PSS'", exception.getMessage());

        kbSignParams.setSigningCertificate(getSigningCert());
        kbSignParams.setDigestAlgorithm(DigestAlgorithm.SHA256);

        kbSignParams.setTagged(true);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("COSE_Sign1 structure shall be untagged!", exception.getMessage());

        kbSignParams.setTagged(false);

        exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, null, kbSignParams));
        assertEquals("keyBindingParameters must not be null", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("DocType must not be null", exception.getMessage());
        keyBindingParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);

        exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("SessionTranscript must not be null", exception.getMessage());
        keyBindingParameters.setSessionTranscript(new InMemoryDocument("not-cbor".getBytes()));

        exception = assertThrows(DSSException.class, () -> service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams));
        assertEquals("Session transcript must be a CBOR object", exception.getMessage());
        keyBindingParameters.setSessionTranscript(buildSessionTranscript());

        ToBeSigned dataToSign = service.getDataToSignForKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(dataToSign, kbSignParams.getDigestAlgorithm(), getPrivateKeyEntry());

        DSSDocument keyBindingSignature = service.createKeyBindingSignature(signedEAA, keyBindingParameters, kbSignParams, signatureValue);
        assertNotNull(keyBindingSignature);

        List<MdocSelectiveDisclosure> disclosures = service.getDisclosures(prepareDisclosuresPayloadParameters());
        DSSDocument keyBindingSignatureWithDisclosures = service.createKeyBindingSignature(signedEAA, disclosures, keyBindingParameters, kbSignParams, signatureValue);
        assertNotNull(keyBindingSignatureWithDisclosures);
    }

    @Test
    void issuePresentationTest() {
        DSSDocument signedEAA = createSignedEAA(payloadParameters, signatureParameters);
        DSSDocument nonCborDoc = new InMemoryDocument("not-cbor-content".getBytes());

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> service.issuePresentation(signedEAA, Collections.emptyList()));
        assertNotNull(exception.getMessage());
        assertTrue(exception.getMessage().contains("issuePresentation"));

        exception = assertThrows(DSSException.class, () -> service.issuePresentation(nonCborDoc, Collections.emptyList(), nonCborDoc));
        assertEquals("The attestation should be a cbor document!", exception.getMessage());

        exception = assertThrows(DSSException.class, () -> service.issuePresentation(signedEAA, Collections.emptyList(), nonCborDoc));
        assertEquals("The keyBinding should be a cbor document!", exception.getMessage());

        List<MdocSelectiveDisclosure> disclosures = service.getDisclosures(prepareDisclosuresPayloadParameters());
        DSSDocument issuerSigned = service.createIssuerSigned(signedEAA, disclosures);
        assertNotNull(issuerSigned);
        assertNotNull(issuerSigned.getName());
        assertNotNull(issuerSigned.getMimeType());

        CBAdESSignatureParameters kbSignParams = new CBAdESSignatureParameters();
        kbSignParams.setDigestAlgorithm(DigestAlgorithm.SHA256);
        kbSignParams.setSigningCertificate(getSigningCert());

        MdocKeyBindingParameters kbParams = new MdocKeyBindingParameters();
        kbParams.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        kbParams.setSessionTranscript(buildSessionTranscript());

        ToBeSigned kbDataToSign = service.getDataToSignForKeyBindingSignature(signedEAA, kbParams, kbSignParams);
        SignatureValue kbSignatureValue = getToken().sign(kbDataToSign, kbSignParams.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument keyBinding = service.createKeyBindingSignature(signedEAA, kbParams, kbSignParams, kbSignatureValue);
        assertNotNull(keyBinding);

        DSSDocument presentation = service.issuePresentation(signedEAA, Collections.emptyList(), keyBinding);
        assertNotNull(presentation);
        assertNotNull(presentation.getName());
        assertNotNull(presentation.getMimeType());
    }

    private MdocPayloadParameters prepareDisclosuresPayloadParameters() {
        MdocPayloadParameters params = new MdocPayloadParameters();
        params.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        params.setSigned(new Date());
        params.setValidFrom(new Date());
        params.setValidUntil(getSigningCert().getNotAfter());
        params.selectivelyDisclosable().setGivenName("John");
        params.selectivelyDisclosable().setFamilyName("Doe");
        return params;
    }

    private DSSDocument createSignedEAA(MdocPayloadParameters params, CBAdESSignatureParameters sigParams) {
        ToBeSigned dataToSign = service.getDataToBeSigned(params, sigParams);
        SignatureValue signatureValue = getToken().sign(dataToSign, sigParams.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signEAA(params, sigParams, signatureValue);
    }

    private DSSDocument buildSessionTranscript() {
        byte[] selectMessage = new byte[]{0x01, 0x02};
        byte[] requestMessage = new byte[]{0x03, 0x04};
        return SessionTranscriptBuilder.nfcHandover(selectMessage, requestMessage)
                .security(EllipticCurve.P_256, getSigningCert().getPublicKey())
                .eReaderKey(getSigningCert().getPublicKey())
                .build();
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
