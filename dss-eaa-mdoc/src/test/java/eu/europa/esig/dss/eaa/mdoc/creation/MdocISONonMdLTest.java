/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocISONonMdLTest extends AbstractMdocPresentationTestIssuance {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());
        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setBirthdate(DSSUtils.getUtcDate(2001, Calendar.JANUARY, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeIssuanceDate(DSSUtils.getUtcDate(2026, Calendar.JUNE, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeExpirationDate(DSSUtils.getUtcDate(2026, Calendar.AUGUST, 31));
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");

        payloadParameters.selectivelyDisclosable().setIssuingAuthority("TEST Authority");
        payloadParameters.selectivelyDisclosable().setDocumentNumber("123456789");

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
    protected CBAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected MdocKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        super.checkEAADigestMatchers(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        List<XmlDigestMatcher> digestMatchers = eaa.getDigestMatchers();
        assertEquals(8, digestMatchers.size());

        boolean familyNameSDFound = false;
        boolean givenNameSDFound = false;
        boolean birthdateSDFound = false;
        boolean issueDateSDFound = false;
        boolean expiryDateSDFound = false;
        boolean issuingCountrySDFound = false;
        boolean issuingAuthoritySDFound = false;
        boolean documentNumberSDFound = false;
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
            } else if ("document_number".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.23220.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("123456789", xmlDigestMatcher.getDisclosableClaim().getValue());
                documentNumberSDFound = true;
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
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertEquals("1.0", eaa.getVersion());
        assertEquals("org.iso.23220.1.mID", eaa.getAttestationDocumentType());
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
