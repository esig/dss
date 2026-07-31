package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
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

class SDJWTServiceTest extends PKIFactoryAccess {

    private SDJWTService service;
    private JAdESSignatureParameters signatureParameters;
    private SDJWTPayloadParameters payloadParameters;

    @BeforeEach
    void init() {
        service = new SDJWTService(getOfflineCertificateVerifier());

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("https://issuer.example.com");
        payloadParameters.setVerifiableCredentialsType("urn:eudi:pid:1");
        payloadParameters.nonSelectivelyDisclosable().setGivenName("John");
        payloadParameters.nonSelectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthority("TEST Authority");
    }

    @Test
    void signAttestationWithDSSDocumentTest() {
        DSSDocument jsonPayload = new InMemoryDocument("{\"hello\":\"world\"}".getBytes(), "payload.json", MimeTypeEnum.JSON);
        DSSDocument nonJsonPayload = new InMemoryDocument("not-json-content".getBytes(), "payload.txt");
        JAdESSignatureParameters params = new JAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToSign((DSSDocument) null, params));
        assertEquals("payload cannot be null!", exception.getMessage());

        exception = assertThrows(DSSException.class, () -> service.getDataToSign(nonJsonPayload, params));
        assertEquals("Payload is not a JSON document!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> service.getDataToSign(jsonPayload, null));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSign(jsonPayload, params));
        assertEquals("Signature level must be JAdES-BASELINE-B!", exception.getMessage());
        params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

        params.setSignaturePackaging(SignaturePackaging.DETACHED);
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSign(jsonPayload, params));
        assertEquals("Signature packaging must be ENVELOPING", exception.getMessage());
        params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSign(jsonPayload, params));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        params.setSigningCertificate(getSigningCert());
        params.setCertificateChain(getCertificateChain());

        ToBeSigned dataToSign = service.getDataToSign(jsonPayload, params);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());

        exception = assertThrows(NullPointerException.class, () -> service.signAttestation((DSSDocument) null, params, signatureValue));
        assertEquals("payload cannot be null!", exception.getMessage());

        exception = assertThrows(DSSException.class, () -> service.signAttestation(nonJsonPayload, params, signatureValue));
        assertEquals("Payload is not a JSON document!", exception.getMessage());

        DSSDocument signedAttestation = service.signAttestation(jsonPayload, params, signatureValue);
        assertNotNull(signedAttestation);
    }

    @Test
    void signAttestationWithPayloadParametersTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToSign(payloadParameters, null));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        JAdESSignatureParameters params = new JAdESSignatureParameters();
        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSign(payloadParameters, params));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        ToBeSigned dataToSign = service.getDataToSign(payloadParameters, signatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());

        exception = assertThrows(NullPointerException.class, () -> service.signAttestation(payloadParameters, null, signatureValue));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        DSSDocument signedAttestation = service.signAttestation(payloadParameters, signatureParameters, signatureValue);
        assertNotNull(signedAttestation);
    }

    @Test
    void getDisclosuresTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> service.generateDisclosures(null));
        assertEquals("SDJWTPayloadParameters cannot be null!", exception.getMessage());

        SDJWTPayloadParameters params = new SDJWTPayloadParameters();

        exception = assertThrows(NullPointerException.class, () -> service.generateDisclosures(params));
        assertEquals("NotBefore date cannot be null!", exception.getMessage());
        params.setNotBeforeDate(new Date());

        exception = assertThrows(NullPointerException.class, () -> service.generateDisclosures(params));
        assertEquals("Expiration date a cannot be null!", exception.getMessage());
        params.setExpirationDate(new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000));

        List<SDJWTSelectiveDisclosure> disclosures = service.generateDisclosures(params);
        assertNotNull(disclosures);
        assertTrue(disclosures.isEmpty());

        params.nonSelectivelyDisclosable().setIssuingAuthority("TEST Authority");
        disclosures = service.generateDisclosures(params);
        assertNotNull(disclosures);
        assertTrue(disclosures.isEmpty());

        params.selectivelyDisclosable().setGivenName("John");
        params.selectivelyDisclosable().setFamilyName("Doe");
        disclosures = service.generateDisclosures(params);
        assertNotNull(disclosures);
        assertEquals(2, disclosures.size());
        for (SDJWTSelectiveDisclosure disclosure : disclosures) {
            assertNotNull(disclosure.getDisclosure());
        }
    }

    @Test
    void keyBindingSignatureTest() {
        DSSDocument signedAttestation = createSignedAttestation(payloadParameters, signatureParameters);

        SDJWTKeyBindingParameters keyBindingParameters = new SDJWTKeyBindingParameters();
        JAdESSignatureParameters kbSignParams = new JAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, null, kbSignParams));
        assertEquals("keyBindingParameters must not be null", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams));
        assertEquals("Audience must not be null", exception.getMessage());
        keyBindingParameters.setAudience("https://verifier.example.org");

        exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams));
        assertEquals("Nonce must not be null", exception.getMessage());
        keyBindingParameters.setNonce("1234567890");

        keyBindingParameters.setIssuanceTime(new Date());

        exception = assertThrows(NullPointerException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, null));
        assertEquals("signatureParameters cannot be null!", exception.getMessage());

        kbSignParams.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
        exception = assertThrows(DSSException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams));
        assertEquals("Signature level must be JAdES_BASELINE_B", exception.getMessage());
        kbSignParams.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

        kbSignParams.setSignaturePackaging(SignaturePackaging.DETACHED);
        exception = assertThrows(DSSException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams));
        assertEquals("Signature packaging must be ENVELOPING", exception.getMessage());
        kbSignParams.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        kbSignParams.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        exception = assertThrows(DSSException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams));
        assertEquals("JWS serialization type must be COMPACT_SERIALIZATION", exception.getMessage());
        kbSignParams.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

        exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        kbSignParams.setSigningCertificate(getSigningCert());
        kbSignParams.setCertificateChain(getCertificateChain());

        ToBeSigned dataToSign = service.getDataToSignForKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(dataToSign, kbSignParams.getDigestAlgorithm(), getPrivateKeyEntry());

        exception = assertThrows(NullPointerException.class, () -> service.createKeyBindingSignature(signedAttestation, null, kbSignParams, signatureValue));
        assertEquals("keyBindingParameters must not be null", exception.getMessage());

        DSSDocument keyBindingSignature = service.createKeyBindingSignature(signedAttestation, keyBindingParameters, kbSignParams, signatureValue);
        assertNotNull(keyBindingSignature);

        DSSDocument keyBindingSignatureWithDisclosures = service.createKeyBindingSignature(signedAttestation, Collections.emptyList(), keyBindingParameters, kbSignParams, signatureValue);
        assertNotNull(keyBindingSignatureWithDisclosures);
    }

    @Test
    void issuePresentationTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> service.issuePresentation(null, Collections.emptyList(), null));
        assertEquals("The attestation cannot be null!", exception.getMessage());

        DSSDocument nonJwsDoc = new InMemoryDocument("not-a-jws-document".getBytes());
        exception = assertThrows(DSSException.class, () -> service.issuePresentation(nonJwsDoc, Collections.emptyList(), null));
        assertEquals("The signed attestation must be a JWS Signature", exception.getMessage());

        DSSDocument signedAttestation = createSignedAttestation(payloadParameters, signatureParameters);
        DSSDocument presentation = service.issuePresentation(signedAttestation, Collections.emptyList(), null);
        assertNotNull(presentation);
        assertNotNull(presentation.getName());
        assertNotNull(presentation.getMimeType());

        SDJWTPayloadParameters sdParams = new SDJWTPayloadParameters();
        sdParams.setIssuer("https://issuer.example.com");
        sdParams.setNotBeforeDate(new Date());
        sdParams.setExpirationDate(getSigningCert().getNotAfter());
        sdParams.selectivelyDisclosable().setGivenName("Jane");
        sdParams.selectivelyDisclosable().setFamilyName("Smith");

        List<SDJWTSelectiveDisclosure> disclosures = service.generateDisclosures(sdParams);
        assertEquals(2, disclosures.size());

        DSSDocument sdSignedAttestation = createSignedAttestation(sdParams, signatureParameters);
        DSSDocument presentationWithDisclosures = service.issuePresentation(sdSignedAttestation, disclosures, null);
        assertNotNull(presentationWithDisclosures);
    }

    private DSSDocument createSignedAttestation(SDJWTPayloadParameters params, JAdESSignatureParameters sigParams) {
        ToBeSigned dataToSign = service.getDataToSign(params, sigParams);
        SignatureValue signatureValue = getToken().sign(dataToSign, sigParams.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signAttestation(params, sigParams, signatureValue);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
