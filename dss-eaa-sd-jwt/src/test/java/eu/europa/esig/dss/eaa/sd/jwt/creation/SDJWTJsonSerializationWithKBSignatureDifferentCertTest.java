package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.test.pki.CertEntitySignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTJsonSerializationWithKBSignatureDifferentCertTest extends AbstractSDJWTTestIssuance {

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
    protected DSSDocument createKeyBindingSignature() {
        if (includeKeyBindingSignature()) {
            JAdESSignatureParameters params = getKeyBindingSignatureParameters();

            DSSDocument signedEAA = signEAA();
            List<SDJWTSelectiveDisclosure> disclosures = getDisclosures();
            SDJWTKeyBindingParameters kbParams = getKeyBindingParameters();

            ToBeSigned dataToSign = getService().getDataToSignForKeyBindingSignature(signedEAA, disclosures, kbParams, params);

            SignatureValue signatureValue;
            try (CertEntitySignatureTokenConnection kbToken = new CertEntitySignatureTokenConnection(getCertEntity(ECDSA_521_USER))) {
                DSSPrivateKeyEntry kbPrivateKeyEntry = kbToken.getKeys().iterator().next();
                signatureValue = kbToken.sign(dataToSign, params.getSignatureAlgorithm(), kbPrivateKeyEntry);
            }

            return getService().createKeyBindingSignature(signedEAA, disclosures, kbParams, params, signatureValue);
        }
        return null;
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
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        super.checkEAADigestMatchers(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        List<XmlDigestMatcher> digestMatchers = eaa.getDigestMatchers();
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

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        assertEquals("https://issuer.example.com", eaa.getIssuer());
        assertEquals("John", eaa.getGivenName());
        assertEquals("Doe", eaa.getFamilyName());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
