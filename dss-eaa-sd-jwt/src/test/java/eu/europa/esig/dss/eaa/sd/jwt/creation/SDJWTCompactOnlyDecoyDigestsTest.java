package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SDJWTCompactOnlyDecoyDigestsTest extends AbstractSDJWTTestIssuance {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("EAA provider");

        payloadParameters.setVerifiableCredentialsType("urn:eudi:eaa:1");
        Digest digest = new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        payloadParameters.nonSelectivelyDisclosable().setGivenName("John");
        payloadParameters.nonSelectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthority("TEST Authority");

        payloadParameters.setDecoyDigestNumber(2);

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
    protected JAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected SDJWTKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertEquals("urn:eudi:eaa:1", eaa.getVerifiableCredentialsTypeUri());
        assertEquals(DigestAlgorithm.SHA256, eaa.getVerifiableCredentialsTypeIntegrityDigestAlgorithm());
        assertArrayEquals(DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()), eaa.getVerifiableCredentialsTypeIntegrityBytes());
        assertEquals(DSSUtils.formatDateToRFC(getSignatureParameters().bLevel().getSigningDate()), DSSUtils.formatDateToRFC(eaa.getNotBefore()));
        assertEquals(DSSUtils.formatDateToRFC(getSigningCert().getNotAfter()), DSSUtils.formatDateToRFC(eaa.getExpiration()));
        assertEquals("EAA provider", eaa.getIssuer());
        assertEquals("TEST Authority", eaa.getDocumentIssuingAuthority());
        assertEquals("John", eaa.getGivenName());
        assertEquals("Doe", eaa.getFamilyName());

        assertEquals(2, eaa.getDigestMatchers().size());

        int sdCounter = 0;
        int orphanCounter = 0;
        for (XmlDigestMatcher xmlDigestMatcher : eaa.getDigestMatchers()) {
            if (DigestMatcherType.EAA_DISCLOSURE == xmlDigestMatcher.getType()) {
                ++sdCounter;
            } else if (DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == xmlDigestMatcher.getType()) {
                ++orphanCounter;
            }
        }
        assertEquals(0, sdCounter);
        assertEquals(2, orphanCounter);
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
