package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class MdocAttestationPresentationNoDisclosuresPresentTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdoc-no-disclosures.cbor");
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

        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertEquals(DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM, xmlDigestMatcher.getType());
            assertFalse(xmlDigestMatcher.isDataFound());
            assertFalse(xmlDigestMatcher.isDataIntact());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
        }
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected boolean orphanSelectivelyDisclosableClaimsPresent() {
        return true;
    }

}
