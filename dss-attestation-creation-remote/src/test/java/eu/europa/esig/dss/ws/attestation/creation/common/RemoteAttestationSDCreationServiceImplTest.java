package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationClaimParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemotePublicKey;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteTokenStatusList;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RemoteAttestationSDCreationServiceImplTest extends PKIFactoryAccess {

    private RemoteAttestationSDCreationServiceImpl attestationSDService;

    @BeforeEach
    void init() {
        attestationSDService = new RemoteAttestationSDCreationServiceImpl();
        attestationSDService.setSdjwtService(getSDJWTService());
        attestationSDService.setMdocService(getMdocService());
    }

    private MdocService getMdocService() {
        return new MdocService(getOfflineCertificateVerifier());
    }

    private SDJWTService getSDJWTService() {
        return new SDJWTService(getOfflineCertificateVerifier());
    }

    @Test
    void issueAttestationTest() {
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

        RemotePublicKey publicKey = new RemotePublicKey();
        publicKey.setPublicKey(getSigningCert().getPublicKey().getEncoded());
        payloadParameters.setDeviceKey(publicKey);

        payloadParameters.setVerifiableCredentialsType("urn:eudi:eaa:1");
        DigestDTO digest = new DigestDTO(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        payloadParameters.setStatusList(new RemoteTokenStatusList(1, "https://pki.nowina.lu/eaa/status_list"));

        RemoteAttestationClaimParameters selectivelyDisclosable = new RemoteAttestationClaimParameters();
        selectivelyDisclosable.setGivenName("John");
        selectivelyDisclosable.setFamilyName("Doe");
        payloadParameters.setSelectivelyDisclosable(selectivelyDisclosable);

        ToBeSignedDTO dataToSign = attestationSDService.getDataToSign(payloadParameters, signatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument signedAttestation = attestationSDService.signAttestation(payloadParameters, signatureParameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedAttestation);

        List<DisclosureDTO> disclosures = attestationSDService.generateDisclosures(payloadParameters);

        RemoteDocument parametersOnlyAttestation = attestationSDService.issueAttestation(signedAttestation, payloadParameters, null);
        RemoteDocument disclosuresOnlyAttestation = attestationSDService.issueAttestation(signedAttestation, new RemoteAttestationPayloadParameters(AttestationForm.SD_JWT), disclosures);
        RemoteDocument allParametersAttestation = attestationSDService.issueAttestation(signedAttestation, payloadParameters, disclosures);

        assertEquals(parametersOnlyAttestation, disclosuresOnlyAttestation);
        assertEquals(parametersOnlyAttestation, allParametersAttestation);
        assertEquals(disclosuresOnlyAttestation, allParametersAttestation);

        Exception exception = assertThrows(NullPointerException.class, () ->
                attestationSDService.issueAttestation(signedAttestation, null, disclosures));
        assertEquals("payloadParameters must be defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                attestationSDService.issueAttestation(signedAttestation, new RemoteAttestationPayloadParameters(), disclosures));
        assertEquals("attestationForm must be defined!", exception.getMessage());

        RemoteDocument emptyDisclosuresAttestation = attestationSDService.issueAttestation(signedAttestation, payloadParameters, Collections.emptyList());
        assertNotEquals(parametersOnlyAttestation, emptyDisclosuresAttestation);
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
