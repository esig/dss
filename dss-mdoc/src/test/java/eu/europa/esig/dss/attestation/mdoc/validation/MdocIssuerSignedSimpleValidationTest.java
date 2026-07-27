package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocIssuerSignedSimpleValidationTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mid-valid.cbor");
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(6, digestMatchers.size());

        boolean pseudonymSDFound = false;
        boolean birthdateSDFound = false;
        boolean issueDateSDFound = false;
        boolean expiryDateSDFound = false;
        boolean issuingCountrySDFound = false;
        boolean issuingAuthoritySDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertTrue(xmlDigestMatcher.isDataFound());
            assertTrue(xmlDigestMatcher.isDataIntact());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("also_known_as".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.etsi.01947201.010101", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("X Man", xmlDigestMatcher.getDisclosableClaim().getValue());
                pseudonymSDFound = true;
            } else if ("birth_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("{\"birth_date\": \"2001-01-01\"}", xmlDigestMatcher.getDisclosableClaim().getValue());
                birthdateSDFound = true;
            } else if ("issue_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2026-06-01", xmlDigestMatcher.getDisclosableClaim().getValue());
                issueDateSDFound = true;
            } else if ("expiry_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2026-08-31", xmlDigestMatcher.getDisclosableClaim().getValue());
                expiryDateSDFound = true;
            } else if ("issuing_country".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingCountrySDFound = true;
            } else if ("issuing_authority".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("TEST Authority", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingAuthoritySDFound = true;
            }
        }
        assertTrue(pseudonymSDFound);
        assertTrue(birthdateSDFound);
        assertTrue(issueDateSDFound);
        assertTrue(expiryDateSDFound);
        assertTrue(issuingCountrySDFound);
        assertTrue(issuingAuthoritySDFound);
    }

}
