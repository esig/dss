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
package eu.europa.esig.dss.cookbook.example.snippets.ws.soap;

// tag::demo[]

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.SignAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationClaimParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPresentationParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters;
import eu.europa.esig.dss.ws.attestation.creation.soap.SoapAttestationCreationServiceImpl;
import eu.europa.esig.dss.ws.attestation.creation.soap.client.SoapAttestationCreationService;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class SoapEAACreationServiceSnippet extends CookbookTools {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // Instantiate the SOAP client
            SoapAttestationCreationService soapClient = new SoapAttestationCreationServiceImpl();
            
            // 1 EAA issuance

            // 1.1 Define signature parameters
            Date signingTime = new Date();
            RemoteSignatureParameters signatureParameters = new RemoteSignatureParameters();
            RemoteBLevelParameters bLevelParameters = new RemoteBLevelParameters();
            bLevelParameters.setSigningDate(signingTime);
            signatureParameters.setBLevelParams(bLevelParameters);
            signatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
            signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // 1.2 Define payload parameters, claims definition
            RemoteAttestationPayloadParameters payloadParameters = new RemoteAttestationPayloadParameters(AttestationFormat.SD_JWT_VC);

            // 1.2.1 Define technical claims
            // NOTE: Ensure the dates are defined for a deterministic behavior
            payloadParameters.setNotBeforeDate(signingTime);
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.MONTH, 3);
            Date expirationTime = calendar.getTime();
            payloadParameters.setExpirationDate(expirationTime);

            payloadParameters.setIssuer("EAA provider");
            payloadParameters.setSubject("good-ecdsa-user");

            // 1.2.2 Define optional claims, as selectively disclosable
            RemoteAttestationClaimParameters selectivelyDisclosable = new RemoteAttestationClaimParameters();
            selectivelyDisclosable.setGivenName("John");
            selectivelyDisclosable.setFamilyName("Doe");
            payloadParameters.setSelectivelyDisclosable(selectivelyDisclosable);

            // Or not selectively disclosable
            RemoteAttestationClaimParameters nonSelectivelyDisclosable = new RemoteAttestationClaimParameters();
            nonSelectivelyDisclosable.setIssuingAuthority("TEST Authority");
            nonSelectivelyDisclosable.setIssuingCountry("LU");
            nonSelectivelyDisclosable.setIssuingAuthorityRegistrationIdentifier("VATLU-123456");
            payloadParameters.setNonSelectivelyDisclosable(nonSelectivelyDisclosable);

            // 1.3 Create DTBS (Data To Be Signed)
            DataToSignAttestationDTO dataToSignAttestationDTO = new DataToSignAttestationDTO(payloadParameters, signatureParameters);
            ToBeSignedDTO dataToSign = soapClient.getDataToSign(dataToSignAttestationDTO);

            // 1.4 Create Signature Value
            SignatureValue signatureValue = signingToken.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, privateKey);

            // 1.5 Sign EAA (ensure the same parameters are used as in #getDataToSign method)
            SignAttestationDTO signAttestationDTO = new SignAttestationDTO(payloadParameters, signatureParameters,
                    new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
            RemoteDocument signedEAA = soapClient.signEAA(signAttestationDTO);

            // 2 Extract selective disclosures
            // NOTE: all, some or none of them may be provided within an Attestation Presentation
            DisclosuresDTO disclosuresDTO = new DisclosuresDTO(payloadParameters);
            List<DisclosureDTO> disclosures = soapClient.getDisclosures(disclosuresDTO);

            // 3 Key Binding signature computation
            
            // 3.1 Create signature parameters
            RemoteSignatureParameters keyBindingSignatureParameters = new RemoteSignatureParameters();
            keyBindingSignatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(privateKey.getCertificate()));
            keyBindingSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // 3.2 Create key binding signature payload parameters
            RemoteKeyBindingParameters keyBindingParameters = new RemoteKeyBindingParameters();
            keyBindingParameters.setEaaType(AttestationFormat.SD_JWT_VC);
            keyBindingParameters.setNonce("123456");
            keyBindingParameters.setAudience("audience");

            // 3.3 Get DTBS (Data To Be Signed) for key binding signature
            DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO =
                    new DataToSignForKeyBindingSignatureDTO(signedEAA, disclosures, keyBindingParameters, keyBindingSignatureParameters);
            dataToSign = soapClient.getDataToSignForKeyBindingSignature(dataToSignForKeyBindingSignatureDTO);
            
            // 3.4 Create signature value
            signatureValue = signingToken.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, privateKey);

            // 3.5 Create key binding signature
            CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO = new CreateKeyBindingSignatureDTO(signedEAA, disclosures, keyBindingParameters,
                    keyBindingSignatureParameters, new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
            RemoteDocument keyBindingSignature = soapClient.createKeyBindingSignature(createKeyBindingSignatureDTO);

            // 4 Issue EAA presentation
            // NOTE: requires signed EAA, (optional) disclosures, 
            // (optional, format specific) key binding signature and EAA presentation parameters
            IssuePresentationDTO issuePresentationDTO = new IssuePresentationDTO(signedEAA, disclosures, keyBindingSignature,
                    new RemoteAttestationPresentationParameters(AttestationFormat.SD_JWT_VC));
            RemoteDocument attestationPresentation = soapClient.issuePresentation(issuePresentationDTO);
        }

    }

}
// end::demo[]