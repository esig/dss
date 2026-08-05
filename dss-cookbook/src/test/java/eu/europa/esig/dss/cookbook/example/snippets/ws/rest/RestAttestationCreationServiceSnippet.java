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
package eu.europa.esig.dss.cookbook.example.snippets.ws.rest;

// tag::demo[]

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.ws.attestation.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssueAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.ParseAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.SignAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationClaimParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationParsingParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPresentationParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters;
import eu.europa.esig.dss.ws.attestation.creation.rest.RestAttestationCreationServiceImpl;
import eu.europa.esig.dss.ws.attestation.creation.rest.RestAttestationPresentationServiceImpl;
import eu.europa.esig.dss.ws.attestation.creation.rest.RestAttestationSDCreationServiceImpl;
import eu.europa.esig.dss.ws.attestation.creation.rest.client.RestAttestationCreationService;
import eu.europa.esig.dss.ws.attestation.creation.rest.client.RestAttestationPresentationService;
import eu.europa.esig.dss.ws.attestation.creation.rest.client.RestAttestationSDCreationService;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class RestAttestationCreationServiceSnippet extends CookbookTools {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // tag::attestation-creation[]

            // import eu.europa.esig.dss.enumerations.AttestationForm;
            // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignAttestationDTO;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.SignAttestationDTO;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationClaimParameters;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
            // import eu.europa.esig.dss.ws.attestation.creation.rest.RestAttestationCreationServiceImpl;
            // import eu.europa.esig.dss.ws.attestation.creation.rest.client.RestAttestationCreationService;
            // import eu.europa.esig.dss.ws.converter.DTOConverter;
            // import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
            // import eu.europa.esig.dss.ws.dto.RemoteDocument;
            // import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
            // import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
            // import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
            // import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

            // ISSUER_1 attestation issuance

            // Instantiate the REST client
            RestAttestationCreationService issuerRestClient = new RestAttestationCreationServiceImpl();

            // ISSUER_1.1 Define signature parameters
            Date signingTime = new Date();
            RemoteSignatureParameters signatureParameters = new RemoteSignatureParameters();
            RemoteBLevelParameters bLevelParameters = new RemoteBLevelParameters();
            bLevelParameters.setSigningDate(signingTime);
            signatureParameters.setBLevelParams(bLevelParameters);
            signatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
            signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // ISSUER_1.2 Define payload parameters, claims definition
            RemoteAttestationPayloadParameters payloadParameters = new RemoteAttestationPayloadParameters(AttestationForm.SD_JWT);

            // ISSUER_1.2.1 Define technical claims
            // NOTE: Ensure the dates are defined for a deterministic behavior
            payloadParameters.setNotBeforeDate(signingTime);
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.MONTH, 3);
            Date expirationTime = calendar.getTime();
            payloadParameters.setExpirationDate(expirationTime);

            payloadParameters.setIssuer("Attestation provider");

            // ISSUER_1.2.2 Define optional claims, as selectively disclosable
            RemoteAttestationClaimParameters selectivelyDisclosable = new RemoteAttestationClaimParameters();
            selectivelyDisclosable.setGivenName("John");
            selectivelyDisclosable.setFamilyName("Doe");
            payloadParameters.setSelectivelyDisclosable(selectivelyDisclosable);

            // Or not selectively disclosable
            RemoteAttestationClaimParameters nonSelectivelyDisclosable = new RemoteAttestationClaimParameters();
            nonSelectivelyDisclosable.setSubject("good-ecdsa-user");
            nonSelectivelyDisclosable.setIssuingAuthority("TEST Authority");
            nonSelectivelyDisclosable.setIssuingCountry("LU");
            nonSelectivelyDisclosable.setIssuingAuthorityRegistrationIdentifier("VATLU-123456");
            payloadParameters.setNonSelectivelyDisclosable(nonSelectivelyDisclosable);

            // ISSUER_1.3 Create DTBS (Data To Be Signed)
            DataToSignAttestationDTO dataToSignAttestationDTO = new DataToSignAttestationDTO(payloadParameters, signatureParameters);
            ToBeSignedDTO dataToSign = issuerRestClient.getDataToSign(dataToSignAttestationDTO);

            // ISSUER_1.4 Create Signature Value
            SignatureValue signatureValue = signingToken.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, privateKey);

            // ISSUER_1.5 Sign attestation (ensure the same parameters are used as in #getDataToSign method)
            SignAttestationDTO signAttestationDTO = new SignAttestationDTO(payloadParameters, signatureParameters,
                    new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
            RemoteDocument signedAttestation = issuerRestClient.signAttestation(signAttestationDTO);

            // end::attestation-creation[]

            // tag::attestation-sd-creation[]
            
            // import eu.europa.esig.dss.enumerations.AttestationForm;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.DisclosuresDTO;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.IssueAttestationDTO;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
            // import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
            // import eu.europa.esig.dss.ws.attestation.creation.rest.RestAttestationSDCreationServiceImpl;
            // import eu.europa.esig.dss.ws.attestation.creation.rest.client.RestAttestationSDCreationService;
            // import eu.europa.esig.dss.ws.dto.RemoteDocument;

            // ISSUER_2 Issue attestation

            RestAttestationSDCreationService issuerSDRestClient = new RestAttestationSDCreationServiceImpl();
            
            // Two possibilities exist (see a and b)

            // ISSUER_2.a Issue attestation using payload parameters
            IssueAttestationDTO issueAttestationDTO = new IssueAttestationDTO(signedAttestation, payloadParameters);
            RemoteDocument attestation = issuerSDRestClient.issueAttestation(issueAttestationDTO);

            // ISSUER_2.b Issue attestation using disclosure list

            // ISSUER_2.b.1 Extract selective disclosures
            // NOTE: all, some or none of them may be provided within an Attestation Presentation
            DisclosuresDTO disclosuresDTO = new DisclosuresDTO(payloadParameters);
            List<DisclosureDTO> disclosures = issuerSDRestClient.generateDisclosures(disclosuresDTO);

            // ISSUER_2.b.2 Generate the attestation with the attached disclosures
            issueAttestationDTO = new IssueAttestationDTO(signedAttestation, AttestationForm.SD_JWT, disclosures);
            attestation = issuerSDRestClient.issueAttestation(issueAttestationDTO);

            // end::attestation-sd-creation[]

            // WALLET_1 Parse obtained attestation

            RestAttestationPresentationService walletRestClient = new RestAttestationPresentationServiceImpl();

            ParseAttestationDTO parseAttestationDTO = new ParseAttestationDTO(attestation,
                    new RemoteAttestationParsingParameters(AttestationForm.SD_JWT));
            RemoteAttestationDocument attestationDocument = walletRestClient.parseAttestation(parseAttestationDTO);

            signedAttestation = attestationDocument.getSignedAttestation();
            disclosures = attestationDocument.getDisclosures();

            // WALLET_2 Key Binding signature computation

            // WALLET_2.1 Create signature parameters
            RemoteSignatureParameters keyBindingSignatureParameters = new RemoteSignatureParameters();
            keyBindingSignatureParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(privateKey.getCertificate()));
            keyBindingSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // WALLET_2.2 Create key binding signature payload parameters
            RemoteKeyBindingParameters keyBindingParameters = new RemoteKeyBindingParameters();
            keyBindingParameters.setAttestationForm(AttestationForm.SD_JWT);
            keyBindingParameters.setNonce("123456");
            keyBindingParameters.setAudience("audience");

            // WALLET_2.3 Get DTBS (Data To Be Signed) for key binding signature
            DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO =
                    new DataToSignForKeyBindingSignatureDTO(signedAttestation, disclosures, keyBindingParameters, keyBindingSignatureParameters);
            dataToSign = walletRestClient.getDataToSignForKeyBindingSignature(dataToSignForKeyBindingSignatureDTO);

            // WALLET_2.4 Create signature value
            signatureValue = signingToken.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, privateKey);

            // WALLET_2.5 Create key binding signature
            CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO = new CreateKeyBindingSignatureDTO(signedAttestation, disclosures, keyBindingParameters,
                    keyBindingSignatureParameters, new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
            RemoteDocument keyBindingSignature = walletRestClient.createKeyBindingSignature(createKeyBindingSignatureDTO);

            // WALLET_3 Issue attestation presentation
            // NOTE: requires signed attestation, (optional) disclosures,
            // (optional, format specific) key binding signature and attestation presentation parameters
            IssuePresentationDTO issuePresentationDTO = new IssuePresentationDTO(signedAttestation, disclosures, keyBindingSignature,
                    new RemoteAttestationPresentationParameters(AttestationForm.SD_JWT));
            RemoteDocument attestationPresentation = walletRestClient.issuePresentation(issuePresentationDTO);
        }

    }

}
// end::demo[]