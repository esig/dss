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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.attestation.mdoc.validation.MdocDeviceResponseDocumentValidator;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTPayloadParameters;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTKeyBindingParameters;
import eu.europa.esig.dss.attestation.sd.jwt.validation.SDJWTCompactDocumentValidator;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocPayloadParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocKeyBindingParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.SessionTranscriptBuilder;
import eu.europa.esig.dss.attestation.mdoc.validation.MdocIssuerSignedDocumentValidator;
import eu.europa.esig.dss.attestation.mdoc.validation.MdocValidationParameters;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.test.pki.CertEntitySignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

/**
 * How to validate an attestation presentation
 */
class AttestationValidationTest extends CookbookTools {

    @Test
    void validateSDJWTPresentation() {
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
            DSSPrivateKeyEntry devicePrivateKey = signingToken.getKeys().get(0);
            CertificateToken deviceCertificate = devicePrivateKey.getCertificate();

            // Create an SD-JWT attestation presentation
            SDJWTPayloadParameters payloadParameters = new SDJWTPayloadParameters();
            payloadParameters.setIssuer("https://issuer.example.com");
            payloadParameters.nonSelectivelyDisclosable().setIssuanceDate(new Date());
            payloadParameters.selectivelyDisclosable().setGivenName("John");
            payloadParameters.selectivelyDisclosable().setFamilyName("Doe");

            JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());
            signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            SDJWTService service = new SDJWTService(commonCertificateVerifier);

            ToBeSigned dataToSign = service.getDataToSign(payloadParameters, signatureParameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedAttestation = service.signAttestation(payloadParameters, signatureParameters, signatureValue);

            List<SDJWTSelectiveDisclosure> disclosures = service.generateDisclosures(payloadParameters);

            SDJWTKeyBindingParameters keyBindingParameters = new SDJWTKeyBindingParameters();
            keyBindingParameters.setIssuanceTime(new Date());
            keyBindingParameters.setAudience("https://verifier.example.org");
            keyBindingParameters.setNonce("nonce-value-from-verifier");

            JAdESSignatureParameters kbSignatureParameters = new JAdESSignatureParameters();
            kbSignatureParameters.setSigningCertificate(deviceCertificate);
            kbSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
            kbSignatureParameters.setIncludeKeyIdentifier(false);
            kbSignatureParameters.setIncludeCertificateChain(false);

            ToBeSigned kbDataToSign = service.getDataToSignForKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters);
            SignatureValue kbSignatureValue = signingToken.sign(kbDataToSign, kbSignatureParameters.getDigestAlgorithm(), devicePrivateKey);
            DSSDocument keyBindingJWT = service.createKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters, kbSignatureValue);

            // tag::sdjwt-presentation-document[]
            // Issue a presentation with both disclosures and a key binding signature
            DSSDocument presentationDocument = service.issuePresentation(signedAttestation, disclosures, keyBindingJWT);
            // end::sdjwt-presentation-document[]

            // tag::attestation-qualification[]
            // import import eu.europa.esig.dss.enumerations.AttestationQualification;
            // end::attestation-qualification[]
            // tag::attestation-validation-auto[]
            // import eu.europa.esig.dss.detailedreport.DetailedReport;
            // import eu.europa.esig.dss.diagnostic.DiagnosticData;
            // tag::attestation-qualification[]
            // import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
            // import eu.europa.esig.dss.simplereport.SimpleReport;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
            // import eu.europa.esig.dss.validation.reports.Reports;

            // Auto-detect format and create validator
            DefaultAttestationDocumentValidator validator =
                    DefaultAttestationDocumentValidator.fromDocument(presentationDocument);

            // Provide a certificate verifier (for signing-certificate chain validation)
            validator.setCertificateVerifier(commonCertificateVerifier);

            // Validate and retrieve the reports
            Reports reports = validator.validateDocument();
            // end::attestation-qualification[]

            DiagnosticData diagnosticData = reports.getDiagnosticData();
            // tag::attestation-qualification[]
            SimpleReport simpleReport = reports.getSimpleReport();
            // end::attestation-qualification[]
            DetailedReport detailedReport = reports.getDetailedReport();
            // end::attestation-validation-auto[]

            // tag::attestation-validation-sdjwt-compact[]
            // import eu.europa.esig.dss.attestation.sd.jwt.validation.SDJWTCompactAttestationPresentationValidator;

            SDJWTCompactDocumentValidator sdJWTValidator =
                    new SDJWTCompactDocumentValidator(presentationDocument);
            sdJWTValidator.setCertificateVerifier(commonCertificateVerifier);

            Reports sdJWTReports = sdJWTValidator.validateDocument();
            // end::attestation-validation-sdjwt-compact[]

            // tag::attestation-diagnostic-attestation-data[]
            // import eu.europa.esig.dss.diagnostic.AttestationWrapper;
            // import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
            // import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;

            // Retrieve all attestation entries from the diagnostic data
            List<AttestationWrapper> attestations = diagnosticData.getAttestations();
            AttestationWrapper attestation = attestations.get(0);

            // Issuer and subject
            String issuer = attestation.getIssuer();
            String subject = attestation.getSubject();

            // Expiration and issuance dates
            Date issuedAt = attestation.getIssuedAt();
            Date expiration = attestation.getExpiration();

            // All payload claims (including nested claims)
            List<ClaimWrapper> claims = new java.util.ArrayList<>(attestation.getAllAttestationPayloadClaims());
            for (ClaimWrapper claim : claims) {
                String name = claim.getName();
                String displayValue = claim.getDisplayValue();
                boolean isSelectivelyDisclosable = claim.isSelectivelyDisclosable();
            }

            // Retrieve a specific claim by name
            ClaimWrapper givenNameClaim = attestation.getClaimByHeaderName("given_name");

            // Only selectively disclosable claims (those disclosed in the presentation)
            List<ClaimWrapper> sdClaims = attestation.getSelectiveDisclosures();

            // Key binding information
            String kbNonce = attestation.getKeyBindingSignatureNonce();
            String kbAudience = attestation.getKeyBindingSignatureAudience();

            // Revocation / revocation list information
            for (AttestationRevocationWrapper revocation : attestation.getAttestationRevocations()) {
                String sourceAddress = revocation.getSourceAddress();
                AttestationStatus status = revocation.getStatus();
            }
            // end::attestation-diagnostic-attestation-data[]

            // tag::attestation-qualification[]
            // Extract attestation qualification:

            // a) Get the first qualification result
            AttestationQualification attestationQualification = simpleReport.getAttestationQualification(simpleReport.getFirstAttestationId());

            // b) Get all qualification results (may be useful when both
            //    QEAA/PuB-EAA and PID qualification levels are expected.
            List<AttestationQualification> attestationQualifications = simpleReport.getAttestationQualifications(simpleReport.getFirstAttestationId());
            // end::attestation-qualification[]
        }
    }

    @Test
    void validateMdocDeviceResponsePresentation() {
        try (SignatureTokenConnection signingToken = new CertEntitySignatureTokenConnection(getCertEntity(ECDSA_USER))) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
            DSSPrivateKeyEntry devicePrivateKey = signingToken.getKeys().get(0);
            CertificateToken deviceCertificate = devicePrivateKey.getCertificate();

            // --- Create an mdoc attestation presentation (setup) ---
            MdocPayloadParameters payloadParameters = new MdocPayloadParameters();
            payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
            payloadParameters.setDeviceKey(deviceCertificate);
            payloadParameters.selectivelyDisclosable().setGivenName("John");
            payloadParameters.selectivelyDisclosable().setFamilyName("Doe");

            CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
            signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            MdocService service = new MdocService(commonCertificateVerifier);

            ToBeSigned dataToSign = service.getDataToSign(payloadParameters, signatureParameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedAttestation = service.signAttestation(payloadParameters, signatureParameters, signatureValue);

            List<MdocIssuerSignedItem> disclosures = service.generateDisclosures(payloadParameters);

            DSSDocument sessionTranscript = SessionTranscriptBuilder
                    .nfcHandover(new byte[]{0x01, 0x02}, new byte[]{0x03, 0x04})
                    .security(EllipticCurve.P_256, deviceCertificate.getPublicKey())
                    .eReaderKey(deviceCertificate.getPublicKey())
                    .build();

            MdocKeyBindingParameters keyBindingParameters = new MdocKeyBindingParameters();
            keyBindingParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
            keyBindingParameters.setSessionTranscript(sessionTranscript);

            CBAdESSignatureParameters kbSignatureParameters = new CBAdESSignatureParameters();
            kbSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            kbSignatureParameters.setSigningCertificate(deviceCertificate);

            ToBeSigned kbDataToSign = service.getDataToSignForKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters);
            SignatureValue kbSignatureValue = signingToken.sign(kbDataToSign, kbSignatureParameters.getDigestAlgorithm(), devicePrivateKey);
            DSSDocument deviceAuthSignature = service.createKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters, kbSignatureValue);

            // tag::mdoc-presentation-document[]
            // Issue a full DeviceResponse (CBOR, with device authentication)
            DSSDocument presentationDocument = service.issuePresentation(signedAttestation, disclosures, deviceAuthSignature);
            // end::mdoc-presentation-document[]

            // tag::attestation-validation-mdoc-device-response[]
            // import eu.europa.esig.dss.attestation.mdoc.validation.MdocDeviceResponseAttestationPresentationValidator;
            // import eu.europa.esig.dss.attestation.mdoc.validation.MdocValidationParameters;

            MdocDeviceResponseDocumentValidator mdocValidator =
                    new MdocDeviceResponseDocumentValidator(presentationDocument);
            mdocValidator.setCertificateVerifier(commonCertificateVerifier);

            // For key-binding validation, provide the session transcript
            MdocValidationParameters validationParameters = new MdocValidationParameters();
            validationParameters.setSessionTranscript(sessionTranscript);
            mdocValidator.setAttestationValidationParameters(validationParameters);

            Reports reports = mdocValidator.validateDocument();
            // end::attestation-validation-mdoc-device-response[]

            // tag::attestation-validation-mdoc-issuer-signed[]
            // import eu.europa.esig.dss.attestation.mdoc.validation.MdocIssuerSignedAttestationPresentationValidator;

            // Issue an IssuerSigned-only presentation (no device authentication)
            DSSDocument issuerSignedDocument = service.issueAttestation(signedAttestation, disclosures);

            MdocIssuerSignedDocumentValidator issuerSignedValidator =
                    new MdocIssuerSignedDocumentValidator(issuerSignedDocument);
            issuerSignedValidator.setCertificateVerifier(commonCertificateVerifier);

            Reports issuerSignedReports = issuerSignedValidator.validateDocument();
            // end::attestation-validation-mdoc-issuer-signed[]
        }
    }

}





