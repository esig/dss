package eu.europa.esig.dss.attestation.sd.jwt.creation;

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

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactWithKBSignatureDifferentCertTest extends AbstractSDJWTTestIssuance {

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
        payloadParameters.setDeviceKeyType("EC");

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/good-cert");

        keyBindingSignatureParameters = new JAdESSignatureParameters();
        keyBindingSignatureParameters.setSigningCertificate(getCertEntity(ECDSA_521_USER).getCertificateToken());
        keyBindingSignatureParameters.setCertificateChain(getCertEntity(ECDSA_521_USER).getCertificateChain().toArray(new CertificateToken[0]));
        keyBindingSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        keyBindingSignatureParameters.setIncludeKeyIdentifier(false);
        keyBindingSignatureParameters.setIncludeCertificateChain(false);

        keyBindingParameters = new SDJWTKeyBindingParameters();
        keyBindingParameters.setIssuanceTime(Date.from(new Date().toInstant().truncatedTo(ChronoUnit.SECONDS)));
        keyBindingParameters.setAudience("https://verifier.example.org");
        keyBindingParameters.setNonce("1234567890");
    }

    @Override
    protected DSSDocument createKeyBindingSignature() {
        if (includeKeyBindingSignature()) {
            JAdESSignatureParameters params = getKeyBindingSignatureParameters();

            DSSDocument signedAttestation = signAttestation();
            List<SDJWTSelectiveDisclosure> disclosures = getDisclosures();
            SDJWTKeyBindingParameters kbParams = getKeyBindingParameters();

            ToBeSigned dataToSign = getService().getDataToSignForKeyBindingSignature(signedAttestation, disclosures, kbParams, params);

            SignatureValue signatureValue;
            try (CertEntitySignatureTokenConnection kbToken = new CertEntitySignatureTokenConnection(getCertEntity(ECDSA_521_USER))) {
                DSSPrivateKeyEntry kbPrivateKeyEntry = kbToken.getKeys().iterator().next();
                signatureValue = kbToken.sign(dataToSign, params.getSignatureAlgorithm(), kbPrivateKeyEntry);
            }

            return getService().createKeyBindingSignature(signedAttestation, disclosures, kbParams, params, signatureValue);
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

        assertEquals(keyBindingParameters.getNonce(), attestation.getKeyBindingSignatureNonce());
        assertEquals(keyBindingParameters.getAudience(), attestation.getKeyBindingSignatureAudience());
        assertEquals(keyBindingParameters.getIssuanceTime().getTime(), attestation.getKeyBindingSignatureIssuanceTime().getTime());
        assertEquals(0, attestation.getOtherKeyBindingPayloadClaims().size());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}



