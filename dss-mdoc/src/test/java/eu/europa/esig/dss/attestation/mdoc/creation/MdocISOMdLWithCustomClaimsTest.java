package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocISOMdLWithCustomClaimsTest extends AbstractMdocIssuerSignedTestCreation {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setDocumentNumber("123456789");

        payloadParameters.selectivelyDisclosable().addClaim("org.iso.23220.1", "custom_field1", "custom_value1");
        payloadParameters.selectivelyDisclosable().addClaim(MdocClaim.create("org.iso.23220.2", "custom_field2", "custom_value2"));
        payloadParameters.selectivelyDisclosable().addClaim(MdocClaim.create("org.iso.23220.3",  3, "custom_field3", "custom_value3"));
        payloadParameters.selectivelyDisclosable().addClaim(MdocClaim.create("org.iso.23220.4",  "custom_field4", "custom_value4", new byte[] { 4 }));
        payloadParameters.selectivelyDisclosable().addClaim(MdocClaim.create("org.iso.23220.5",  5, "custom_field5", "custom_value5", new byte[] { 5 }));

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected MdocPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(8, digestMatchers.size());

        boolean familyNameSDFound = false;
        boolean givenNameSDFound = false;
        boolean documentNumberSDFound = false;
        boolean custom1SDFound = false;
        boolean custom2SDFound = false;
        boolean custom3SDFound = false;
        boolean custom4SDFound = false;
        boolean custom5SDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                familyNameSDFound = true;
            } else if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("John", xmlDigestMatcher.getDisclosableClaim().getValue());
                givenNameSDFound = true;
            } else if ("document_number".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("123456789", xmlDigestMatcher.getDisclosableClaim().getValue());
                documentNumberSDFound = true;
            } else if ("custom_field1".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("custom_value1", xmlDigestMatcher.getDisclosableClaim().getValue());
                custom1SDFound = true;
            } else if ("custom_field2".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.2", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("custom_value2", xmlDigestMatcher.getDisclosableClaim().getValue());
                custom2SDFound = true;
            } else if ("custom_field3".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.3", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("custom_value3", xmlDigestMatcher.getDisclosableClaim().getValue());
                assertEquals(3, xmlDigestMatcher.getDisclosableClaim().getId().intValue());
                custom3SDFound = true;
            } else if ("custom_field4".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.4", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("custom_value4", xmlDigestMatcher.getDisclosableClaim().getValue());
                Digest claimDigest = new DefaultMdocSelectiveDisclosureBuilder().build(MdocClaim.create("org.iso.23220.4",
                                xmlDigestMatcher.getDisclosableClaim().getId().intValue(), "custom_field4", "custom_value4", new byte[]{4}))
                        .computeDigest(xmlDigestMatcher.getDigestMethod());
                assertArrayEquals(claimDigest.getValue(), xmlDigestMatcher.getDigestValue());
                custom4SDFound = true;
            } else if ("custom_field5".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.5", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("custom_value5", xmlDigestMatcher.getDisclosableClaim().getValue());
                assertEquals(5, xmlDigestMatcher.getDisclosableClaim().getId().intValue());
                Digest claimDigest = new DefaultMdocSelectiveDisclosureBuilder().build(
                        MdocClaim.create("org.iso.23220.5", 5, "custom_field5", "custom_value5", new byte[]{5}))
                        .computeDigest(xmlDigestMatcher.getDigestMethod());
                assertArrayEquals(claimDigest.getValue(), xmlDigestMatcher.getDigestValue());
                custom5SDFound = true;
            }
        }
        assertTrue(familyNameSDFound);
        assertTrue(documentNumberSDFound);
        assertTrue(givenNameSDFound);
        assertTrue(custom1SDFound);
        assertTrue(custom2SDFound);
        assertTrue(custom3SDFound);
        assertTrue(custom4SDFound);
        assertTrue(custom5SDFound);
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertEquals("1.0", attestation.getVersion());
        assertEquals("org.iso.23220.1.mID", attestation.getAttestationDocumentType());

        List<ClaimWrapper> otherClaims = attestation.getOtherClaims();
        assertEquals(5, otherClaims.size());

        boolean custom1SDFound = false;
        boolean custom2SDFound = false;
        boolean custom3SDFound = false;
        boolean custom4SDFound = false;
        boolean custom5SDFound = false;
        for (ClaimWrapper claimWrapper : otherClaims) {
            if ("custom_field1".equals(claimWrapper.getName())) {
                assertEquals("org.iso.23220.1", claimWrapper.getNamespace());
                assertEquals("custom_value1", claimWrapper.getText());
                custom1SDFound = true;
            } else if ("custom_field2".equals(claimWrapper.getName())) {
                assertEquals("org.iso.23220.2", claimWrapper.getNamespace());
                assertEquals("custom_value2", claimWrapper.getText());
                custom2SDFound = true;
            } else if ("custom_field3".equals(claimWrapper.getName())) {
                assertEquals("org.iso.23220.3", claimWrapper.getNamespace());
                assertEquals("custom_value3", claimWrapper.getText());
                custom3SDFound = true;
            } else if ("custom_field4".equals(claimWrapper.getName())) {
                assertEquals("org.iso.23220.4", claimWrapper.getNamespace());
                assertEquals("custom_value4", claimWrapper.getText());
                custom4SDFound = true;
            } else if ("custom_field5".equals(claimWrapper.getName())) {
                assertEquals("org.iso.23220.5", claimWrapper.getNamespace());
                assertEquals("custom_value5", claimWrapper.getText());
                custom5SDFound = true;
            }
        }
        assertTrue(custom1SDFound);
        assertTrue(custom2SDFound);
        assertTrue(custom3SDFound);
        assertTrue(custom4SDFound);
        assertTrue(custom5SDFound);
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
