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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.attestation.mdoc.pki.PKICWTIdentifierListSource;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocISOMdLIdentifierListTest extends AbstractMdocPresentationTestIssuance {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO18013_5_MDL_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());
        payloadParameters.setIdentifierList(new byte[] { 1 }, "https://pki.nowina.lu/eaa/identifier_list", getCertificate(GOOD_CA));

        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setBirthdate(DSSUtils.getUtcDate(2001, Calendar.JANUARY, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeIssuanceDate(DSSUtils.getUtcDate(2026, Calendar.JUNE, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeExpirationDate(DSSUtils.getUtcDate(2026, Calendar.AUGUST, 31));
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");
        payloadParameters.selectivelyDisclosable().setIssuingAuthority("TEST Authority");
        payloadParameters.selectivelyDisclosable().setDocumentNumber("123456789");
        payloadParameters.selectivelyDisclosable().setPortrait(Utils.fromBase64("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAA+SURBVDhPY/hPIWBAFyAVUNeAr7VN/z/6BiMLwcH3qTP/vzexRhceNQCbAW9lVHBiogyg2AUj3QByAMUGAAAAZ7ueWC72UQAAAABJRU5ErkJggg=="));

        MdocDrivingPrivilege mdocDrivingPrivilege = new MdocDrivingPrivilege("B");
        mdocDrivingPrivilege.setIssueDate(DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1));
        mdocDrivingPrivilege.setExpiryDate(DSSUtils.getUtcDate(2030, Calendar.JANUARY, 1));
        payloadParameters.selectivelyDisclosable().setDrivingPrivileges(mdocDrivingPrivilege);

        payloadParameters.selectivelyDisclosable().setDistinguishingSign("DN");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected AttestationRevocationSource getEAAStatusSource() {
        return new PKICWTIdentifierListSource(getCertEntityRepository(), getCertEntity(GOOD_CA));
    }

    @Override
    protected void checkEAARevocations(DiagnosticData diagnosticData) {
        super.checkEAARevocations(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        List<AttestationRevocationWrapper> eaaStatuses = eaa.getAttestationRevocations();
        assertEquals(1, eaaStatuses.size());
        AttestationRevocationWrapper eaaRevocationWrapper = eaaStatuses.get(0);
        assertEquals(AttestationStatus.VALID, eaaRevocationWrapper.getStatus());
        assertEquals("application/identifierlist+cwt", eaaRevocationWrapper.getType());

        FoundCertificatesProxy foundCertificates = eaaRevocationWrapper.foundCertificates();
        List<RelatedCertificateWrapper> relatedCertificates = foundCertificates.getRelatedCertificates();
        assertEquals(1, relatedCertificates.size());

        RelatedCertificateWrapper certificateWrapper = relatedCertificates.get(0);
        assertEquals(2, certificateWrapper.getOrigins().size());
        assertEquals(2, certificateWrapper.getReferences().size());
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
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                familyNameSDFound = true;
            } else if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("John", xmlDigestMatcher.getDisclosableClaim().getValue());
                givenNameSDFound = true;
            } else if ("birth_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2001-01-01", xmlDigestMatcher.getDisclosableClaim().getValue());
                birthdateSDFound = true;
            } else if ("issue_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2026-06-01T00:00:00Z", xmlDigestMatcher.getDisclosableClaim().getValue());
                issueDateSDFound = true;
            } else if ("expiry_date".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("2026-08-31T00:00:00Z", xmlDigestMatcher.getDisclosableClaim().getValue());
                expiryDateSDFound = true;
            } else if ("issuing_country".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingCountrySDFound = true;
            } else if ("issuing_authority".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("TEST Authority", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingAuthoritySDFound = true;
            } else if ("document_number".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("123456789", xmlDigestMatcher.getDisclosableClaim().getValue());
                documentNumberSDFound = true;
            } else if ("portrait".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAA+SURBVDhPY/hPIWBAFyAVUNeAr7VN/z/6BiMLwcH3qTP/vzexRhceNQCbAW9lVHBiogyg2AUj3QByAMUGAAAAZ7ueWC72UQAAAABJRU5ErkJggg==", xmlDigestMatcher.getDisclosableClaim().getValue());
                portraitSDFound = true;
            } else if ("driving_privileges".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.iso.18013.5.1", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertTrue(Utils.isStringNotEmpty(xmlDigestMatcher.getDisclosableClaim().getValue()));
                drivingPrivilegesSDFound = true;
            } else if ("un_distinguishing_sign".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
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

        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertEquals("1.0", eaa.getVersion());
        assertEquals("org.iso.18013.5.1.mDL", eaa.getAttestationDocumentType());

        assertArrayEquals(new byte[] { 1 }, eaa.getIdentifierListId());
        assertEquals("https://pki.nowina.lu/eaa/identifier_list", eaa.getIdentifierListUri());
        assertArrayEquals(getCertificate(GOOD_CA).getEncoded(), eaa.getIdentifierListCertificate());

        assertNull(eaa.getStatusIndex());
        assertNull(eaa.getStatusUri());
        assertNull(eaa.getStatusCertificate());
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
