package eu.europa.esig.dss.attestation.sd.jwt.creation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;

class SDJWTCompactPartialDisclosureTest extends AbstractSDJWTTestCreation {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("Attestation provider");
        payloadParameters.nonSelectivelyDisclosable().setSubject(DSSASN1Utils.getSubjectCommonName(getSigningCert()));
        payloadParameters.setDeviceKey(getSigningCert().getPublicKey());

        payloadParameters.setVerifiableCredentialsType("urn:eudi:eaa:1");
        Digest digest = new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setIssuingAuthority("TEST Authority");
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");
        payloadParameters.selectivelyDisclosable().setIssuingAuthorityRegistrationIdentifier("VATLU-123456");

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
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
        assertEquals(5, digestMatchers.size());

        boolean familyNameSDFound = false;
        boolean givenNameSDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            if (xmlDigestMatcher.getType().equals(DigestMatcherType.SELECTIVE_DISCLOSURE)) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim());
                if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                    assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                    familyNameSDFound = true;
                } else if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                    assertEquals("John", xmlDigestMatcher.getDisclosableClaim().getValue());
                    givenNameSDFound = true;
                } else if ("issuing_country".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                    fail();
                } else if ("issuing_authority".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                    fail();
                } else if ("iss_reg_id".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                    fail();
                }
            }
        }
        assertTrue(familyNameSDFound);
        assertTrue(givenNameSDFound);
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected List<SDJWTSelectiveDisclosure> getDisclosures() {
        // Return only some of the claims to disclose
        List<SDJWTSelectiveDisclosure> disclosures = super.getDisclosures();
        return disclosures.subList(0, 2);
    }

    @Override
    protected boolean orphanSelectiveDisclosuresPresent() {
        return true;
    }

    @Override
    protected int getNumberOfOrphanSDClaims() {
        return 3;
    }
}