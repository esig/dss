package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationPayloadProxy;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocAttestationPresentationMultipleDisclosuresInvalidTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdoc-multiple-invalid-disclosures.cbor");
    }

    @Override
    protected DSSDocument getSessionTranscript() {
        return new InMemoryDocument(Utils.fromBase64("g9gYWFiiAGMxLjABggHYGFhLpAECIAEhWCDmILgoADAfDnPTJcLCKsri+0H8M2gJG1CZ2AGPauUViyJYIGv2G0k6HwOm/5bKiSPBeaY/aQljf2bhjfHjdJuNf2Ct2BhYS6QBAiABIVgg5iC4KAAwHw5z0yXCwirK4vtB/DNoCRtQmdgBj2rlFYsiWCBr9htJOh8Dpv+WyokjwXmmP2kJY39m4Y3x43SbjX9grYJCAQJCAwQ="));
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(11, digestMatchers.size());

        boolean familyNameSDFound = false;
        boolean givenNameSDFound = false;
        boolean birthdateSDFound = false;
        boolean issueDateSDFound = false;
        boolean expiryDateSDFound = false;
        boolean issuingCountrySDFound = false;
        boolean issuingAuthoritySDFound = false;
        boolean documentNumberSDFound = false;
        boolean portraitSDFound = false;
        boolean drivingPrivilegesSDFound = false;
        boolean distinguishingSignSDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertTrue(xmlDigestMatcher.isDataFound());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertFalse(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("White", xmlDigestMatcher.getDisclosableClaim().getValue());
                familyNameSDFound = true;
            } else if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertFalse(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("Ben", xmlDigestMatcher.getDisclosableClaim().getValue());
                givenNameSDFound = true;
            } else if ("birth_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2001-01-01", xmlDigestMatcher.getDisclosableClaim().getValue());
                birthdateSDFound = true;
            } else if ("issue_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2026-06-01T00:00:00Z", xmlDigestMatcher.getDisclosableClaim().getValue());
                issueDateSDFound = true;
            } else if ("expiry_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2026-08-31T00:00:00Z", xmlDigestMatcher.getDisclosableClaim().getValue());
                expiryDateSDFound = true;
            } else if ("issuing_country".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingCountrySDFound = true;
            } else if ("issuing_authority".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("TEST Authority", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingAuthoritySDFound = true;
            } else if ("document_number".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("123456789", xmlDigestMatcher.getDisclosableClaim().getValue());
                documentNumberSDFound = true;
            } else if ("portrait".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAA+SURBVDhPY/hPIWBAFyAVUNeAr7VN/z/6BiMLwcH3qTP/vzexRhceNQCbAW9lVHBiogyg2AUj3QByAMUGAAAAZ7ueWC72UQAAAABJRU5ErkJggg==", xmlDigestMatcher.getDisclosableClaim().getValue());
                portraitSDFound = true;
            } else if ("driving_privileges".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertTrue(Utils.isStringNotEmpty(xmlDigestMatcher.getDisclosableClaim().getValue()));
                drivingPrivilegesSDFound = true;
            } else if ("un_distinguishing_sign".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("DN", xmlDigestMatcher.getDisclosableClaim().getValue());
                distinguishingSignSDFound = true;
            }
        }
        assertTrue(familyNameSDFound);
        assertTrue(givenNameSDFound);
        assertTrue(birthdateSDFound);
        assertTrue(issueDateSDFound);
        assertTrue(expiryDateSDFound);
        assertTrue(issuingCountrySDFound);
        assertTrue(issuingAuthoritySDFound);
        assertTrue(documentNumberSDFound);
        assertTrue(portraitSDFound);
        assertTrue(drivingPrivilegesSDFound);
        assertTrue(distinguishingSignSDFound);
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestationWrapper = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        AttestationPayloadProxy attestationPayload = attestationWrapper.getPayload();
        assertNull(attestationPayload.getGivenName());
        assertNull(attestationPayload.getFamilyName());
    }

}
