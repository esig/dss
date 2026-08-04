package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactIatAndSubSelectivelyDisclosableTest extends AbstractSDJWTTestCreation {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    private Date issuanceDate;
    private Date expiration;

    @BeforeEach
    void init() {
        issuanceDate = new Date();
        expiration = new Date(issuanceDate.getTime() + 3600 * 1000);

        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setExpirationDate(expiration);
        payloadParameters.setIssuer("https://issuer.example.com");

        payloadParameters.selectivelyDisclosable().setIssuanceDate(issuanceDate);
        payloadParameters.selectivelyDisclosable().setSubject("good-user");

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/good-cert");
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
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        boolean iatFound = false;
        boolean subFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("iat".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                iatFound = true;
            } else if ("sub".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim().getName());
                subFound = true;
            }
        }
        assertTrue(iatFound);
        assertTrue(subFound);
    }

    @Override
    protected void checkClaims(final DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        assertEquals("https://issuer.example.com", attestation.getIssuer());
        assertEquals("good-user", attestation.getSubject());
        assertEquals(expiration.toInstant().getEpochSecond(), attestation.getExpiration().toInstant().getEpochSecond());
        assertEquals(issuanceDate.toInstant().getEpochSecond(), attestation.getIssuedAt().toInstant().getEpochSecond());
    }
    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
