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
package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.attestation.mdoc.validation.MdocValidationParameters;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.attestation.AttestationDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.ClaimDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.ClaimValueDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DrivingPrivilegeDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationClaimParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteIdentifierList;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPresentationParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteTokenStatusList;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemotePublicKey;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemoteAttestationCreationServiceImplTest extends PKIFactoryAccess {

    private RemoteAttestationCreationServiceImpl attestationService;

    private String signingAlias;

    @BeforeEach
    void init() {
        attestationService = new RemoteAttestationCreationServiceImpl();
        attestationService.setSdjwtService(getSDJWTService());
        attestationService.setMdocService(getMdocService());
    }

    private MdocService getMdocService() {
        return new MdocService(getOfflineCertificateVerifier());
    }

    private SDJWTService getSDJWTService() {
        return new SDJWTService(getOfflineCertificateVerifier());
    }

    @Test
    void testSDJWTVC() {
        signingAlias = ECDSA_USER;

        Date signingTime = new Date();

        RemoteSignatureParameters signatureParameters = new RemoteSignatureParameters();
        RemoteBLevelParameters bLevelParameters = new RemoteBLevelParameters();
        bLevelParameters.setSigningDate(signingTime);
        signatureParameters.setBLevelParams(bLevelParameters);
        signatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        RemoteAttestationPayloadParameters payloadParameters = new RemoteAttestationPayloadParameters(AttestationForm.SD_JWT);

        payloadParameters.setNotBeforeDate(signingTime);
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 3);
        Date expirationTime = calendar.getTime();
        payloadParameters.setExpirationDate(expirationTime);

        payloadParameters.setIssuer("Attestation provider");

        signingAlias = ECDSA_521_USER;

        RemotePublicKey publicKey = new RemotePublicKey();
        publicKey.setPublicKey(getSigningCert().getPublicKey().getEncoded());
        payloadParameters.setDeviceKey(publicKey);

        payloadParameters.setVerifiableCredentialsType("urn:eudi:eaa:1");
        DigestDTO digest = new DigestDTO(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        payloadParameters.setStatusList(new RemoteTokenStatusList(1, "https://pki.nowina.lu/eaa/status_list"));
        payloadParameters.setCategory("urn:etsi:esi:eaa:eu:qualified");

        RemoteAttestationClaimParameters selectivelyDisclosable = new RemoteAttestationClaimParameters();
        selectivelyDisclosable.setGivenName("John");
        selectivelyDisclosable.setFamilyName("Doe");
        payloadParameters.setSelectivelyDisclosable(selectivelyDisclosable);

        RemoteAttestationClaimParameters nonSelectivelyDisclosable = new RemoteAttestationClaimParameters();
        nonSelectivelyDisclosable.setSubject("good-ecdsa-user");
        nonSelectivelyDisclosable.setIssuingAuthority("TEST Authority");
        nonSelectivelyDisclosable.setIssuingCountry("LU");
        nonSelectivelyDisclosable.setIssuingAuthorityRegistrationIdentifier("VATLU-123456");
        payloadParameters.setNonSelectivelyDisclosable(nonSelectivelyDisclosable);

        List<ClaimDTO> petsArray = new ArrayList<>();
        ClaimValueDTO petsValue = new ClaimValueDTO();
        petsValue.setArrayValue(petsArray);
        ClaimDTO pets = new ClaimDTO("pets", petsValue, true);
        pets.setSelectivelyDisclosable(true);

        List<ClaimDTO> bellaObject = new ArrayList<>();
        bellaObject.add(new ClaimDTO("name", new ClaimValueDTO("Bella"), true));
        bellaObject.add(new ClaimDTO("type", new ClaimValueDTO("dog"), true));
        ClaimValueDTO bellaValue = new ClaimValueDTO();
        bellaValue.setObjectValue(bellaObject);
        petsArray.add(new ClaimDTO(bellaValue, true));

        List<ClaimDTO> slinkyObject = new ArrayList<>();
        slinkyObject.add(new ClaimDTO("name", new ClaimValueDTO("Slinky"), true));
        slinkyObject.add(new ClaimDTO("type", new ClaimValueDTO("cat"), true));
        ClaimValueDTO slinkyValue = new ClaimValueDTO();
        slinkyValue.setObjectValue(slinkyObject);
        petsArray.add(new ClaimDTO(slinkyValue, true));

        payloadParameters.getSelectivelyDisclosable().setOtherClaims(Collections.singletonList(pets));

        signingAlias = ECDSA_USER;

        ToBeSignedDTO dataToSign = attestationService.getDataToSign(payloadParameters, signatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument signedAttestation = attestationService.signAttestation(payloadParameters, signatureParameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedAttestation);

        List<DisclosureDTO> disclosures = attestationService.getDisclosures(payloadParameters);

        signingAlias = ECDSA_521_USER;

        RemoteSignatureParameters keyBindingSignatureParameters = new RemoteSignatureParameters();
        keyBindingSignatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
        keyBindingSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

        RemoteKeyBindingParameters keyBindingParameters = new RemoteKeyBindingParameters();
        keyBindingParameters.setAttestationForm(AttestationForm.SD_JWT);
        keyBindingParameters.setNonce("123456");
        keyBindingParameters.setAudience("audience");

        dataToSign = attestationService.getDataToSignForKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, keyBindingSignatureParameters);
        assertNotNull(dataToSign);
        signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA512, getPrivateKeyEntry());

        RemoteDocument keyBindingSignature = attestationService.createKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters,
                keyBindingSignatureParameters, new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(keyBindingSignature);

        RemoteDocument attestationPresentation = attestationService.issuePresentation(signedAttestation, disclosures, keyBindingSignature,
                new RemoteAttestationPresentationParameters(AttestationForm.SD_JWT));

        InMemoryDocument iMD = new InMemoryDocument(attestationPresentation.getBytes());
        DiagnosticData diagnosticData = validate(iMD, null);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertEquals(AttestationProfile.SD_JWT_VC, attestation.getAttestationProfile());

        assertEquals("urn:eudi:eaa:1", attestation.getVerifiableCredentialsTypeUri());
        assertEquals(DigestAlgorithm.SHA256, attestation.getVerifiableCredentialsTypeIntegrityDigestAlgorithm());
        assertArrayEquals(DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()), attestation.getVerifiableCredentialsTypeIntegrityBytes());
        assertEquals(DSSUtils.formatDateToRFC(signingTime), DSSUtils.formatDateToRFC(attestation.getNotBefore()));
        assertEquals(DSSUtils.formatDateToRFC(expirationTime), DSSUtils.formatDateToRFC(attestation.getExpiration()));
        assertEquals("Attestation provider", attestation.getIssuer());
        assertEquals("good-ecdsa-user", attestation.getSubject());
        assertEquals("TEST Authority", attestation.getDocumentIssuingAuthority());
        assertEquals("LU", attestation.getDocumentIssuingAuthorityCountry());
        assertEquals("VATLU-123456", attestation.getIssuingRegistrationIdentifier());
        assertEquals("John", attestation.getGivenName());
        assertEquals("Doe", attestation.getFamilyName());

        assertEquals("urn:etsi:esi:eaa:eu:qualified", attestation.getCategory());

        assertEquals(1, attestation.getStatusIndex());
        assertEquals("https://pki.nowina.lu/eaa/status_list", attestation.getStatusUri());

        assertArrayEquals(getSigningCert().getPublicKey().getEncoded(), attestation.getDevicePublicKey());

        List<ClaimWrapper> otherClaims = attestation.getOtherClaims();
        assertEquals(1, otherClaims.size());

        ClaimWrapper petsClaimWrapper = otherClaims.get(0);
        assertEquals("pets", petsClaimWrapper.getName());
        assertEquals(2, petsClaimWrapper.getList().size());

        boolean bellaFound = false;
        boolean slinkyFound = false;
        for (ClaimWrapper pet : petsClaimWrapper.getList()) {
            assertNull(pet.getName());

            Map<String, ClaimWrapper> petObject = pet.getMap();
            assertEquals(2, petObject.size());
            if ("Bella".equals(petObject.get("name").getText())) {
                assertEquals("dog", petObject.get("type").getText());
                bellaFound = true;
            } else if ("Slinky".equals(petObject.get("name").getText())) {
                assertEquals("cat", petObject.get("type").getText());
                slinkyFound = true;
            }
        }
        assertTrue(bellaFound);
        assertTrue(slinkyFound);
    }

    @Test
    void testMdoc() {
        signingAlias = ECDSA_USER;

        Date signingTime = new Date();

        RemoteSignatureParameters signatureParameters = new RemoteSignatureParameters();
        RemoteBLevelParameters bLevelParameters = new RemoteBLevelParameters();
        bLevelParameters.setSigningDate(signingTime);
        signatureParameters.setBLevelParams(bLevelParameters);
        signatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        signingAlias = ECDSA_521_USER;

        RemoteAttestationPayloadParameters payloadParameters = new RemoteAttestationPayloadParameters(AttestationForm.MDOC);

        payloadParameters.setDocType(MdocConstants.ISO18013_5_MDL_DOC_TYPE);
        RemotePublicKey publicKey = new RemotePublicKey();
        publicKey.setCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
        payloadParameters.setDeviceKey(publicKey);

        Calendar calendar = Calendar.getInstance();
        Date signingDate = calendar.getTime();
        payloadParameters.setSigned(signingDate);

        calendar.add(Calendar.DATE, -1);
        Date validFrom = calendar.getTime();
        payloadParameters.setValidFrom(validFrom);

        calendar.add(Calendar.MONTH, 3);
        Date validUntil = calendar.getTime();
        payloadParameters.setValidUntil(validUntil);

        calendar.add(Calendar.MONTH, -2);
        Date nextUpdate = calendar.getTime();
        payloadParameters.setExpectedUpdate(nextUpdate);

        payloadParameters.setIdentifierList(new RemoteIdentifierList(
                new byte[] { 1 }, "https://pki.nowina.lu/eaa/identifier_list", RemoteCertificateConverter.toRemoteCertificate(getCertificate(GOOD_CA))));

        RemoteAttestationClaimParameters selectivelyDisclosable = new RemoteAttestationClaimParameters();
        selectivelyDisclosable.setFamilyName("Doe");
        selectivelyDisclosable.setGivenName("John");
        selectivelyDisclosable.setBirthdate(DSSUtils.getUtcDate(2001, Calendar.JANUARY, 1));
        selectivelyDisclosable.setAdministrativeIssuanceDate(DSSUtils.getUtcDate(2026, Calendar.JUNE, 1));
        selectivelyDisclosable.setAdministrativeExpirationDate(DSSUtils.getUtcDate(2026, Calendar.AUGUST, 31));
        selectivelyDisclosable.setIssuingCountry("LU");

        selectivelyDisclosable.setIssuingAuthority("TEST Authority");
        selectivelyDisclosable.setIssuingAuthorityRegistrationIdentifier("VATLU-123456789");
        selectivelyDisclosable.setDocumentNumber("123456789");

        DrivingPrivilegeDTO drivingPrivilege = new DrivingPrivilegeDTO("B");
        drivingPrivilege.setIssueDate(DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1));
        drivingPrivilege.setExpiryDate(DSSUtils.getUtcDate(2030, Calendar.JANUARY, 1));
        selectivelyDisclosable.setDrivingPrivileges(Collections.singletonList(drivingPrivilege));

        payloadParameters.setSelectivelyDisclosable(selectivelyDisclosable);

        signingAlias = ECDSA_USER;

        ToBeSignedDTO dataToSign = attestationService.getDataToSign(payloadParameters, signatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument signedAttestation = attestationService.signAttestation(payloadParameters, signatureParameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedAttestation);

        List<DisclosureDTO> disclosures = attestationService.getDisclosures(payloadParameters);

        signingAlias = ECDSA_521_USER;

        RemoteSignatureParameters keyBindingSignatureParameters = new RemoteSignatureParameters();
        keyBindingSignatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
        keyBindingSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

        RemoteKeyBindingParameters keyBindingParameters = new RemoteKeyBindingParameters();
        keyBindingParameters.setAttestationForm(AttestationForm.MDOC);
        keyBindingParameters.setSessionTranscript(new RemoteDocument(Utils.fromHex("80")));
        keyBindingParameters.setDocType(MdocConstants.ISO18013_5_MDL_DOC_TYPE);

        dataToSign = attestationService.getDataToSignForKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, keyBindingSignatureParameters);
        assertNotNull(dataToSign);
        signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA512, getPrivateKeyEntry());

        RemoteDocument keyBindingSignature = attestationService.createKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters,
                keyBindingSignatureParameters, new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(keyBindingSignature);

        RemoteDocument attestationPresentation = attestationService.issuePresentation(signedAttestation, disclosures, keyBindingSignature,
                new RemoteAttestationPresentationParameters(AttestationForm.MDOC));

        InMemoryDocument iMD = new InMemoryDocument(attestationPresentation.getBytes());
        DiagnosticData diagnosticData = validate(iMD, new InMemoryDocument(Utils.fromHex("80")));

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertEquals(AttestationProfile.ISO_IEC_MDOC, attestation.getAttestationProfile());

        assertEquals("1.0", attestation.getVersion());
        assertEquals("org.iso.18013.5.1.mDL", attestation.getAttestationDocumentType());

        assertEquals(DSSUtils.formatDateToRFC(signingDate), DSSUtils.formatDateToRFC(attestation.getIssuedAt()));
        assertEquals(DSSUtils.formatDateToRFC(validFrom), DSSUtils.formatDateToRFC(attestation.getNotBefore()));
        assertEquals(DSSUtils.formatDateToRFC(validUntil), DSSUtils.formatDateToRFC(attestation.getExpiration()));
        assertEquals(DSSUtils.formatDateToRFC(nextUpdate), DSSUtils.formatDateToRFC(attestation.getNextUpdate()));

        assertArrayEquals(new byte[] { 1 }, attestation.getIdentifierListId());
        assertEquals("https://pki.nowina.lu/eaa/identifier_list", attestation.getIdentifierListUri());
        assertArrayEquals(getCertificate(GOOD_CA).getEncoded(), attestation.getIdentifierListCertificate());

        assertEquals("John", attestation.getGivenName());
        assertEquals("Doe", attestation.getFamilyName());
        assertEquals("2001-01-01T00:00:00Z", DSSUtils.formatDateToRFC(attestation.getBirthdate()));
        assertEquals("2026-06-01T00:00:00Z", DSSUtils.formatDateToRFC(attestation.getAdministrativeIssuanceDate()));
        assertEquals("2026-08-31T00:00:00Z", DSSUtils.formatDateToRFC(attestation.getAdministrativeExpirationDate()));
        assertEquals("LU", attestation.getDocumentIssuingAuthorityCountry());
        assertEquals("TEST Authority", attestation.getDocumentIssuingAuthority());
        assertEquals("VATLU-123456789", attestation.getIssuingRegistrationIdentifier());
        assertEquals("123456789", attestation.getDocumentNumber());

        DrivingPrivilegesClaimWrapper drivingPrivileges = attestation.getDrivingPrivileges();
        assertNotNull(drivingPrivileges);
        assertEquals(1, Utils.collectionSize(drivingPrivileges.getDrivingPrivileges()));

        DrivingPrivilegeClaimWrapper drivingPrivilegeClaimWrapper = drivingPrivileges.getDrivingPrivileges().get(0);
        assertEquals("B", drivingPrivilegeClaimWrapper.getVehicleCategoryCode().getText());
        assertEquals("2020-01-01T00:00:00Z", DSSUtils.formatDateToRFC(drivingPrivilegeClaimWrapper.getIssueDate().getDateTime()));
        assertEquals("2030-01-01T00:00:00Z", DSSUtils.formatDateToRFC(drivingPrivilegeClaimWrapper.getExpiryDate().getDateTime()));
    }

    private DiagnosticData validate(DSSDocument doc, DSSDocument sessionTranscript) {
        AttestationDocumentValidator validator = DefaultAttestationDocumentValidator.fromDocument(doc);
        if (sessionTranscript != null) {
            MdocValidationParameters mdocValidationParameters = new MdocValidationParameters();
            mdocValidationParameters.setSessionTranscript(sessionTranscript);
            validator.setAttestationValidationParameters(mdocValidationParameters);
        }
        validator.setCertificateVerifier(getCompleteCertificateVerifier());

        Reports reports = validator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();
        if (Utils.isCollectionNotEmpty(simpleReport.getAttestationIdList())) {
            assertNotEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        }

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<AttestationWrapper> attestationList = diagnosticData.getAttestations();
        for (AttestationWrapper attestation : attestationList) {
            for (XmlDigestMatcher xmlDigestMatcher : attestation.getDigestMatchers()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());
            }
            List<SignatureWrapper> attestationSignatures = attestation.getAttestationSignatures();
            assertEquals(1, Utils.collectionSize(attestationSignatures));
            assertTrue(attestationSignatures.get(0).isSignatureIntact());
            assertTrue(attestationSignatures.get(0).isSignatureValid());
            assertTrue(attestationSignatures.get(0).isStructuralValidationValid());

            SignatureWrapper keyBindingSignature = attestation.getKeyBindingSignature();
            if (keyBindingSignature != null) {
                assertTrue(keyBindingSignature.isSignatureIntact());
                assertTrue(keyBindingSignature.isSignatureValid());
                assertTrue(keyBindingSignature.isStructuralValidationValid());
            }
        }
        return diagnosticData;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
