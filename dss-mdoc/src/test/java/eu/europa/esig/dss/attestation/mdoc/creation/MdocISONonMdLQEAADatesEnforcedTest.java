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
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonX509URLCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocISONonMdLQAttestationDatesEnforcedTest extends AbstractMdocPresentationTestIssuance {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    private Date signingDate;
    private Date validFrom;
    private Date validUntil;
    private Date nextUpdate;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        Calendar calendar = Calendar.getInstance();
        signingDate = calendar.getTime();

        calendar.add(Calendar.DATE, -1);
        validFrom = calendar.getTime();

        calendar.add(Calendar.MONTH, 3);
        validUntil = calendar.getTime();

        calendar.add(Calendar.MONTH, -2);
        nextUpdate = calendar.getTime();

        payloadParameters.setSigned(signingDate);
        payloadParameters.setValidFrom(validFrom);
        payloadParameters.setValidUntil(validUntil);
        payloadParameters.setExpectedUpdate(nextUpdate);

        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setBirthdate(DSSUtils.getUtcDate(2001, Calendar.JANUARY, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeIssuanceDate(DSSUtils.getUtcDate(2026, Calendar.JUNE, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeExpirationDate(DSSUtils.getUtcDate(2026, Calendar.AUGUST, 31));
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");

        payloadParameters.selectivelyDisclosable().setIssuingAuthority("TEST Authority");
        payloadParameters.selectivelyDisclosable().setIssuingAuthorityRegistrationIdentifier("VATLU-123456789");
        payloadParameters.selectivelyDisclosable().setDocumentNumber("123456789");

        payloadParameters.setStatusList(1, "https://pki.nowina.lu/eaa/status_list");
        payloadParameters.setCategory("urn:etsi:esi:attestation:eu:qualified");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        signatureParameters.setIncludeKeyIdentifier(false);
        signatureParameters.setX509Url("https://pki.nowina.lu/eaa/qeaa.crt");
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);
        CommonX509URLCertificateSource x509URLCertificateSource = new CommonX509URLCertificateSource();
        x509URLCertificateSource.addCertificate("https://pki.nowina.lu/eaa/qeaa.crt", getSigningCert());
        documentValidator.setSigningCertificateSource(x509URLCertificateSource);
        return documentValidator;
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
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(10, digestMatchers.size());

        boolean familyNameSDFound = false;
        boolean givenNameSDFound = false;
        boolean birthdateSDFound = false;
        boolean issueDateSDFound = false;
        boolean expiryDateSDFound = false;
        boolean issuingCountrySDFound = false;
        boolean issuingAuthoritySDFound = false;
        boolean documentNumberSDFound = false;
        boolean registrationIdSDFound = false;
        boolean categorySDFound = false;
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
            } else if ("iss_reg_id".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.etsi.01947201.010101", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("VATLU-123456789", xmlDigestMatcher.getDisclosableClaim().getValue());
                registrationIdSDFound = true;
            } else if ("category".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("org.etsi.01947201.010101", xmlDigestMatcher.getDisclosableClaim().getNamespace());
                assertEquals("urn:etsi:esi:attestation:eu:qualified", xmlDigestMatcher.getDisclosableClaim().getValue());
                categorySDFound = true;
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
        assertTrue(registrationIdSDFound);
        assertTrue(categorySDFound);
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertEquals("1.0", attestation.getVersion());
        assertEquals("org.iso.23220.1.mID", attestation.getAttestationDocumentType());

        assertEquals(DSSUtils.formatDateToRFC(signingDate), DSSUtils.formatDateToRFC(attestation.getIssuedAt()));
        assertEquals(DSSUtils.formatDateToRFC(validFrom), DSSUtils.formatDateToRFC(attestation.getNotBefore()));
        assertEquals(DSSUtils.formatDateToRFC(validUntil), DSSUtils.formatDateToRFC(attestation.getExpiration()));
        assertEquals(DSSUtils.formatDateToRFC(nextUpdate), DSSUtils.formatDateToRFC(attestation.getNextUpdate()));

        assertEquals(1, attestation.getStatusIndex());
        assertEquals("https://pki.nowina.lu/eaa/status_list", attestation.getStatusUri());
        assertNull(attestation.getStatusCertificate());
        assertEquals("urn:etsi:esi:attestation:eu:qualified", attestation.getCategory());
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        super.checkCertificates(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        SignatureWrapper signatureWrapper = attestation.getAttestationSignatures().get(0);
        List<RelatedCertificateWrapper> relatedCertificatesByRefOrigin = signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL);
        assertEquals(1, relatedCertificatesByRefOrigin.size());

        List<CertificateRefWrapper> references = relatedCertificatesByRefOrigin.get(0).getReferences();
        assertEquals(2, references.size());

        boolean signCertRefFound = false;
        boolean x5uRefFound = false;
        for (CertificateRefWrapper certificateRefWrapper : references) {
            if (CertificateRefOrigin.SIGNING_CERTIFICATE == certificateRefWrapper.getOrigin()) {
                assertNotNull(certificateRefWrapper.getDigestAlgoAndValue());
                assertEquals(DigestAlgorithm.SHA256, certificateRefWrapper.getDigestMethod());
                signCertRefFound = true;
            } else if (CertificateRefOrigin.X509_URL == certificateRefWrapper.getOrigin()) {
                assertEquals("https://pki.nowina.lu/eaa/qeaa.crt", certificateRefWrapper.getX509Url());
                x5uRefFound = true;
            }
        }
        assertTrue(signCertRefFound);
        assertTrue(x5uRefFound);
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
