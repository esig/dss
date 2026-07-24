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
import eu.europa.esig.dss.attestation.mdoc.validation.MdocDeviceResponseAttestationDocumentValidator;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTPayloadParameters;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTKeyBindingParameters;
import eu.europa.esig.dss.attestation.sd.jwt.validation.SDJWTCompactAttestationDocumentValidator;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocSelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocPayloadParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocKeyBindingParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.SessionTranscriptBuilder;
import eu.europa.esig.dss.attestation.mdoc.validation.MdocIssuerSignedAttestationDocumentValidator;
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
 * How to validate an EAA presentation
 */
class AttestationValidationTest extends CookbookTools {

    @Test
    void validateSDJWTEAAPresentation() {
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
            DSSPrivateKeyEntry devicePrivateKey = signingToken.getKeys().get(0);
            CertificateToken deviceCertificate = devicePrivateKey.getCertificate();

            // Create an SD-JWT EAA presentation
            SDJWTPayloadParameters payloadParameters = new SDJWTPayloadParameters();
            payloadParameters.setIssuer("https://issuer.example.com");
            payloadParameters.setIssuanceDate(new Date());
            payloadParameters.selectivelyDisclosable().setGivenName("John");
            payloadParameters.selectivelyDisclosable().setFamilyName("Doe");

            JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());
            signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            SDJWTService service = new SDJWTService(commonCertificateVerifier);

            ToBeSigned dataToSign = service.getDataToBeSigned(payloadParameters, signatureParameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedEAA = service.signEAA(payloadParameters, signatureParameters, signatureValue);

            List<SDJWTSelectiveDisclosure> disclosures = service.getDisclosures(payloadParameters);

            SDJWTKeyBindingParameters keyBindingParameters = new SDJWTKeyBindingParameters();
            keyBindingParameters.setIssuanceTime(new Date());
            keyBindingParameters.setAudience("https://verifier.example.org");
            keyBindingParameters.setNonce("nonce-value-from-verifier");

            JAdESSignatureParameters kbSignatureParameters = new JAdESSignatureParameters();
            kbSignatureParameters.setSigningCertificate(deviceCertificate);
            kbSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
            kbSignatureParameters.setIncludeKeyIdentifier(false);
            kbSignatureParameters.setIncludeCertificateChain(false);

            ToBeSigned kbDataToSign = service.getDataToSignForKeyBindingSignature(signedEAA, disclosures, keyBindingParameters, kbSignatureParameters);
            SignatureValue kbSignatureValue = signingToken.sign(kbDataToSign, kbSignatureParameters.getDigestAlgorithm(), devicePrivateKey);
            DSSDocument keyBindingJWT = service.createKeyBindingSignature(signedEAA, disclosures, keyBindingParameters, kbSignatureParameters, kbSignatureValue);

            // tag::sdjwt-presentation-document[]
            // Issue a presentation with both disclosures and a key binding signature
            DSSDocument presentationDocument = service.issuePresentation(signedEAA, disclosures, keyBindingJWT);
            // end::sdjwt-presentation-document[]

            // tag::eaa-qualification[]
            // import import eu.europa.esig.dss.enumerations.EAAQualification;
            // end::eaa-qualification[]
            // tag::eaa-validation-auto[]
            // import eu.europa.esig.dss.detailedreport.DetailedReport;
            // import eu.europa.esig.dss.diagnostic.DiagnosticData;
            // tag::eaa-qualification[]
            // import eu.europa.esig.dss.attestation.common.validation.DefaultEAAPresentationValidator;
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
            // end::eaa-qualification[]

            DiagnosticData diagnosticData = reports.getDiagnosticData();
            // tag::eaa-qualification[]
            SimpleReport simpleReport = reports.getSimpleReport();
            // end::eaa-qualification[]
            DetailedReport detailedReport = reports.getDetailedReport();
            // end::eaa-validation-auto[]

            // tag::eaa-validation-sdjwt-compact[]
            // import eu.europa.esig.dss.attestation.jwt.validation.SDJWTCompactEAAPresentationValidator;

            SDJWTCompactAttestationDocumentValidator sdJWTValidator =
                    new SDJWTCompactAttestationDocumentValidator(presentationDocument);
            sdJWTValidator.setCertificateVerifier(commonCertificateVerifier);

            Reports sdJWTReports = sdJWTValidator.validateDocument();
            // end::eaa-validation-sdjwt-compact[]

            // tag::eaa-diagnostic-eaa-data[]
            // import eu.europa.esig.dss.diagnostic.EAAWrapper;
            // import eu.europa.esig.dss.diagnostic.EAARevocationWrapper;
            // import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;

            // Retrieve all EAA entries from the diagnostic data
            List<AttestationWrapper> eaas = diagnosticData.getEAAs();
            AttestationWrapper eaa = eaas.get(0);

            // Issuer and subject
            String issuer = eaa.getIssuer();
            String subject = eaa.getEAASubject();

            // Expiration and issuance dates
            Date issuedAt = eaa.getEAAIssuedAt();
            Date expiration = eaa.getEAAExpiration();

            // All payload claims (including nested claims)
            List<ClaimWrapper> claims = new java.util.ArrayList<>(eaa.getAllEAAPayloadClaims());
            for (ClaimWrapper claim : claims) {
                String name = claim.getName();
                String displayValue = claim.getDisplayValue();
                boolean isSelectivelyDisclosable = claim.isSelectivelyDisclosable();
            }

            // Retrieve a specific claim by name
            ClaimWrapper givenNameClaim = eaa.getClaimByHeaderName("given_name");

            // Only selectively disclosable claims (those disclosed in the presentation)
            List<ClaimWrapper> sdClaims = eaa.getSelectivelyDisclosableClaims();

            // Key binding information
            String kbNonce = eaa.getKeyBindingSignatureNonce();
            String kbAudience = eaa.getKeyBindingSignatureAudience();

            // Revocation / revocation list information
            for (AttestationRevocationWrapper revocation : eaa.getAttestationRevocations()) {
                String sourceAddress = revocation.getSourceAddress();
                AttestationStatus status = revocation.getStatus();
            }
            // end::eaa-diagnostic-eaa-data[]

            // tag::eaa-qualification[]
            // Extract EAA qualification:

            // a) Get the first qualification result
            AttestationQualification attestationQualification = simpleReport.getEAAQualification(simpleReport.getFirstEAAId());

            // b) Get all qualification results (may be useful when both
            //    QEAA/PuB-EAA and PID qualification levels are expected.
            List<AttestationQualification> attestationQualifications = simpleReport.getEAAQualifications(simpleReport.getFirstEAAId());
            // end::eaa-qualification[]
        }
    }

    @Test
    void validateMdocDeviceResponsePresentation() {
        try (SignatureTokenConnection signingToken = new CertEntitySignatureTokenConnection(getCertEntity(ECDSA_USER))) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
            DSSPrivateKeyEntry devicePrivateKey = signingToken.getKeys().get(0);
            CertificateToken deviceCertificate = devicePrivateKey.getCertificate();

            // --- Create an mdoc EAA presentation (setup) ---
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

            ToBeSigned dataToSign = service.getDataToBeSigned(payloadParameters, signatureParameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedEAA = service.signEAA(payloadParameters, signatureParameters, signatureValue);

            List<MdocSelectiveDisclosure> disclosures = service.getDisclosures(payloadParameters);

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

            ToBeSigned kbDataToSign = service.getDataToSignForKeyBindingSignature(signedEAA, disclosures, keyBindingParameters, kbSignatureParameters);
            SignatureValue kbSignatureValue = signingToken.sign(kbDataToSign, kbSignatureParameters.getDigestAlgorithm(), devicePrivateKey);
            DSSDocument deviceAuthSignature = service.createKeyBindingSignature(signedEAA, disclosures, keyBindingParameters, kbSignatureParameters, kbSignatureValue);

            // tag::mdoc-presentation-document[]
            // Issue a full DeviceResponse (CBOR, with device authentication)
            DSSDocument presentationDocument = service.issuePresentation(signedEAA, disclosures, deviceAuthSignature);
            // end::mdoc-presentation-document[]

            // tag::eaa-validation-mdoc-device-response[]
            // import eu.europa.esig.dss.attestation.mdoc.validation.MdocDeviceResponseEAAPresentationValidator;
            // import eu.europa.esig.dss.attestation.mdoc.validation.MdocValidationParameters;

            MdocDeviceResponseAttestationDocumentValidator mdocValidator =
                    new MdocDeviceResponseAttestationDocumentValidator(presentationDocument);
            mdocValidator.setCertificateVerifier(commonCertificateVerifier);

            // For key-binding validation, provide the session transcript
            MdocValidationParameters validationParameters = new MdocValidationParameters();
            validationParameters.setSessionTranscript(sessionTranscript);
            mdocValidator.setEAAValidationParameters(validationParameters);

            Reports reports = mdocValidator.validateDocument();
            // end::eaa-validation-mdoc-device-response[]

            // tag::eaa-validation-mdoc-issuer-signed[]
            // import eu.europa.esig.dss.attestation.mdoc.validation.MdocIssuerSignedEAAPresentationValidator;

            // Issue an IssuerSigned-only presentation (no device authentication)
            DSSDocument issuerSignedDocument = service.createIssuerSigned(signedEAA, disclosures);

            MdocIssuerSignedAttestationDocumentValidator issuerSignedValidator =
                    new MdocIssuerSignedAttestationDocumentValidator(issuerSignedDocument);
            issuerSignedValidator.setCertificateVerifier(commonCertificateVerifier);

            Reports issuerSignedReports = issuerSignedValidator.validateDocument();
            // end::eaa-validation-mdoc-issuer-signed[]
        }
    }

}





