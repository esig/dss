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
package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIntegrityClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStatusClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlVerifiableCredentialsTypeClaim;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EAACategory;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ETSI194721ConformanceCheckTest extends AbstractTestCheck {

    @Test
    void sdjwtBasicValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void mdocBasicValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("test-value");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void technicalValidityNotYetValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() + 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void technicalValidityNoLongerValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 600000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setExpiration(notAfter);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void administrativeValidityNoLongerValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim administrativeIssuance = new XmlClaim();
        administrativeIssuance.setDateTime(new Date(System.currentTimeMillis() - 600000));
        xmlAttestationPayload.setAdministrativeIssuanceDate(administrativeIssuance);

        XmlClaim administrativeExpiration = new XmlClaim();
        administrativeExpiration.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setAdministrativeExpirationDate(administrativeExpiration);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void administrativeValidityNotYetValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim administrativeIssuance = new XmlClaim();
        administrativeIssuance.setDateTime(new Date(System.currentTimeMillis() + 60000));
        xmlAttestationPayload.setAdministrativeIssuanceDate(administrativeIssuance);

        XmlClaim administrativeExpiration = new XmlClaim();
        administrativeExpiration.setDateTime(new Date(administrativeIssuance.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setAdministrativeExpirationDate(administrativeExpiration);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void sdjwtAdministrativeValidityNotCompleteTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim administrativeIssuance = new XmlClaim();
        administrativeIssuance.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setAdministrativeIssuanceDate(administrativeIssuance);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void mdocAdministrativeValidityNotCompleteTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim administrativeIssuance = new XmlClaim();
        administrativeIssuance.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setAdministrativeIssuanceDate(administrativeIssuance);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("test-value");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void mdocMDLNamespacesConformanceValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("TEST Authority");
        issuingAuthority.setName("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("12345");
        documentNumber.setName("document_number");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim pseudonym = new XmlClaim();
        pseudonym.setText("X Man");
        pseudonym.setName("also_known_as");
        pseudonym.setNamespace("org.etsi.01947201.010101");
        xmlAttestationPayload.setPseudonym(pseudonym);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void mdocMDLNamespacesConformanceNonMDLNamespaceTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("TEST Authority");
        issuingAuthority.setName("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("12345");
        documentNumber.setName("document_number");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim pseudonym = new XmlClaim();
        pseudonym.setText("X Man");
        pseudonym.setName("also_known_as");
        pseudonym.setNamespace("org.iso.23220.1");
        xmlAttestationPayload.setPseudonym(pseudonym);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
        assertTrue(constraints.get(0).getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.EAA_MDOC_NAMESPACE_CONFORMANCE)));
    }

    @Test
    void mdocMDLNamespacesConformanceMDLNotPresentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("TEST Authority");
        issuingAuthority.setName("issuing_authority_unicode");
        issuingAuthority.setNamespace("org.etsi.01947201.010101");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("12345");
        documentNumber.setName("document_number");
        documentNumber.setNamespace("org.etsi.01947201.010101");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim pseudonym = new XmlClaim();
        pseudonym.setText("X Man");
        pseudonym.setName("also_known_as");
        pseudonym.setNamespace("org.etsi.01947201.010101");
        xmlAttestationPayload.setPseudonym(pseudonym);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
        assertTrue(constraints.get(0).getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.EAA_MDOC_NAMESPACE_CONFORMANCE)));
    }

    @Test
    void mdocNonMDLNamespacesConformanceValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("eu.europa.ec.eudi.pid.1");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("TEST Authority");
        issuingAuthority.setName("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("12345");
        documentNumber.setName("document_number");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim pseudonym = new XmlClaim();
        pseudonym.setText("X Man");
        pseudonym.setName("also_known_as");
        pseudonym.setNamespace("org.iso.23220.1");
        xmlAttestationPayload.setPseudonym(pseudonym);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void mdocNonMDLNamespacesConformanceInvalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("eu.europa.ec.eudi.pid.1");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("TEST Authority");
        issuingAuthority.setName("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("12345");
        documentNumber.setName("document_number");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim pseudonym = new XmlClaim();
        pseudonym.setText("X Man");
        pseudonym.setName("also_known_as");
        pseudonym.setNamespace("org.etsi.01947201.010101");
        xmlAttestationPayload.setPseudonym(pseudonym);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
        assertTrue(constraints.get(0).getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.EAA_MDOC_NAMESPACE_CONFORMANCE)));
    }

    @Test
    void mdocDocumentNumberAbsentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void mdocIssuingAuthorityAbsentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("test-value");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void qeaaIssuingAuthorityAbsentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim shortLived = new XmlClaim();
        xmlAttestationPayload.setShortLived(shortLived);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim category = new XmlClaim();
        category.setText(EAACategory.EU_QEAA.getUrn());
        xmlAttestationPayload.setCategory(category);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void pubeaaIssuingAuthorityAbsentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim shortLived = new XmlClaim();
        xmlAttestationPayload.setShortLived(shortLived);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim category = new XmlClaim();
        category.setText(EAACategory.EU_PUBEAA.getUrn());
        xmlAttestationPayload.setCategory(category);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void qeaaIssuingCountryAbsentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("VAT-12345");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim shortLived = new XmlClaim();
        xmlAttestationPayload.setShortLived(shortLived);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim category = new XmlClaim();
        category.setText(EAACategory.EU_QEAA.getUrn());
        xmlAttestationPayload.setCategory(category);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void pubeaaIssuingCountryAbsentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("VAT-12345");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim shortLived = new XmlClaim();
        xmlAttestationPayload.setShortLived(shortLived);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim category = new XmlClaim();
        category.setText(EAACategory.EU_PUBEAA.getUrn());
        xmlAttestationPayload.setCategory(category);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void qeaaIssuingCountryPresentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("VAT-12345");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim issuingCountry = new XmlClaim();
        issuingCountry.setText("LU");
        xmlAttestationPayload.setIssuingCountry(issuingCountry);

        XmlClaim shortLived = new XmlClaim();
        xmlAttestationPayload.setShortLived(shortLived);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim category = new XmlClaim();
        category.setText(EAACategory.EU_QEAA.getUrn());
        xmlAttestationPayload.setCategory(category);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void pubeaaIssuingCountryPresentTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("VAT-12345");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        XmlClaim issuingCountry = new XmlClaim();
        issuingCountry.setText("LU");
        xmlAttestationPayload.setIssuingCountry(issuingCountry);

        XmlClaim shortLived = new XmlClaim();
        xmlAttestationPayload.setShortLived(shortLived);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlClaim category = new XmlClaim();
        category.setText(EAACategory.EU_PUBEAA.getUrn());
        xmlAttestationPayload.setCategory(category);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void shortLivedWithStatusTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("org.iso.18013.5.1.mDL");

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        xmlAttestationPayload.setShortLived(new XmlClaim());
        xmlAttestationPayload.setStatus(new XmlStatusClaim());

        XmlClaim documentNumber = new XmlClaim();
        documentNumber.setText("test-value");
        documentNumber.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setDocumentNumber(documentNumber);

        XmlClaim issuingAuthority = new XmlClaim();
        issuingAuthority.setText("issuing_authority");
        issuingAuthority.setNamespace("org.iso.18013.5.1");
        xmlAttestationPayload.setIssuingAuthority(issuingAuthority);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    // TODO : disabled until review in ETSI TS 119 472-1
    @Disabled
    @Test
    void sdjwtStatusConformanceInvalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        xmlAttestationPayload.setStatus(new XmlStatusClaim());

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void sdjwtStatusConformanceValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        XmlIntegrityClaim xmlIntegrityClaim = new XmlIntegrityClaim();
        xmlIntegrityClaim.setDigestMethod(DigestAlgorithm.SHA256);
        xmlIntegrityClaim.setDigestValue(new byte[]{ 1, 2 , 3});
        xmlVerifiableCredentialsTypeClaim.setIntegrity(xmlIntegrityClaim);
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        XmlStatusClaim statusClaim = new XmlStatusClaim();
        XmlClaim type = new XmlClaim();
        type.setText("revocation type");
        XmlClaim purpose = new XmlClaim();
        purpose.setText("revocation purpose");
        XmlClaim index = new XmlClaim();
        index.setNumber(BigInteger.ONE);
        XmlClaim uri = new XmlClaim();
        uri.setText("revocation uri");
        statusClaim.setType(type);
        statusClaim.setPurpose(purpose);
        statusClaim.setIndex(index);
        statusClaim.setUri(uri);

        xmlAttestationPayload.setStatus(statusClaim);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
        assertNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void sdjwtNoVctTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

    @Test
    void sdjwtNoVctIntegrityTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);

        XmlAttestationSignature presentationSignature = new XmlAttestationSignature();
        XmlSignature signature = new XmlSignature();
        presentationSignature.setSignature(signature);
        xmlAttestation.getAttestationSignature().add(presentationSignature);

        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(System.currentTimeMillis() - 60000));
        xmlAttestationPayload.setNotBefore(notBefore);

        XmlClaim notAfter = new XmlClaim();
        notAfter.setDateTime(new Date(notBefore.getDateTime().getTime() + 3600 * 1000));
        xmlAttestationPayload.setExpiration(notAfter);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        ETSI194721ConformanceCheck etsi194721ConformanceCheck = new ETSI194721ConformanceCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new Date(), new LevelConstraintWrapper(constraint));
        etsi194721ConformanceCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();

        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
        assertNotNull(constraints.get(0).getAdditionalInfo());
    }

}
