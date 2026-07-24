package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationPayloadProxy;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class SDJWTCompactNoDisclosuresValidationTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/sd-jwt-compact-no-disclosures.json");
    }

    @Override
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        List<XmlDigestMatcher> digestMatchers = eaa.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertEquals(DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM, xmlDigestMatcher.getType());
            assertFalse(xmlDigestMatcher.isDataFound());
            assertFalse(xmlDigestMatcher.isDataIntact());
            assertNull(xmlDigestMatcher.getDisclosableClaim());
        }
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestationWrapper = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        AttestationPayloadProxy eaaPayload = attestationWrapper.getPayload();
        assertNull(eaaPayload.getGivenName());
        assertNull(eaaPayload.getFamilyName());
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
    protected boolean orphanSelectivelyDisclosableClaimsPresent() {
        return true;
    }

}
