package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTJsonSerializationWithKBSignatureDifferentCertTest extends AbstractSDJWTWithKBTestCreation {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    private SDJWTKeyBindingParameters keyBindingParameters;
    private JAdESSignatureParameters keyBindingSignatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("https://issuer.example.com");
        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.setDeviceKey(getCertEntity(ECDSA_521_USER).getCertificateToken().getPublicKey());
        payloadParameters.setDeviceKeyType("RSA");

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/good-cert");

        keyBindingSignatureParameters = new JAdESSignatureParameters();
        keyBindingSignatureParameters.setSigningCertificate(getCertEntity(ECDSA_521_USER).getCertificateToken());
        keyBindingSignatureParameters.setCertificateChain(getCertEntity(ECDSA_521_USER).getCertificateChain().toArray(new CertificateToken[0]));
        keyBindingSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        keyBindingSignatureParameters.setIncludeKeyIdentifier(false);
        keyBindingSignatureParameters.setIncludeCertificateChain(false);

        keyBindingParameters = new SDJWTKeyBindingParameters();
        keyBindingParameters.setIssuanceTime(new Date());
        keyBindingParameters.setAudience("https://verifier.example.org");
        keyBindingParameters.setNonce("1234567890");
    }

    @Override
    protected String getDeviceSigningAlias() {
        return ECDSA_521_USER;
    }

    @Override
    protected SDJWTPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected JAdESSignatureParameters getKeyBindingSignatureParameters() {
        return keyBindingSignatureParameters;
    }

    @Override
    protected SDJWTKeyBindingParameters getKeyBindingParameters() {
        return keyBindingParameters;
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        boolean givenNameSDFound = false;
        boolean familyNameSDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                givenNameSDFound = true;
            } else if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                familyNameSDFound = true;
            }
        }
        assertTrue(givenNameSDFound);
        assertTrue(familyNameSDFound);
    }

    @Override
    protected void checkClaims(final DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        assertEquals("https://issuer.example.com", attestation.getIssuer());
        assertEquals("John", attestation.getGivenName());
        assertEquals("Doe", attestation.getFamilyName());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
