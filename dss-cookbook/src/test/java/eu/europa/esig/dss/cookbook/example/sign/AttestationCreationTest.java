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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.attestation.common.creation.TokenStatusList;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocKeyBindingParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocPayloadParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocSelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.attestation.mdoc.creation.SessionTranscriptBuilder;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaim;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimArray;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimObject;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTKeyBindingParameters;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTPayloadParameters;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.test.pki.CertEntitySignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

/**
 * How to create an attestation
 */
class AttestationCreationTest extends CookbookTools {

    @Test
    void createSDJWT() {
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            DSSPrivateKeyEntry devicePrivateKey = signingToken.getKeys().get(0);
            CertificateToken deviceCertificate = devicePrivateKey.getCertificate();

            // tag::sdjwt-payload-parameters[]
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaim;
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimArray;
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimObject;
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTDisclosure;
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTPayloadParameters;

            SDJWTPayloadParameters payloadParameters = new SDJWTPayloadParameters();

            // Configuration of technical claims
            payloadParameters.setIssuer("https://issuer.example.com"); // "iss" claim

            // Configuration of selectively disclosable known claims
            payloadParameters.selectivelyDisclosable().setEmail("john.doe@example.com");
            payloadParameters.selectivelyDisclosable().setPhoneNumber("+352XXXXXXX");

            // Configuration of non selectively disclosable known claims
            payloadParameters.nonSelectivelyDisclosable().setSubject("subject"); // "sub" claim
            payloadParameters.nonSelectivelyDisclosable().setIssuanceDate(new Date()); // "iat" claim
            payloadParameters.nonSelectivelyDisclosable().setGivenName("John"); // "given_name"
            payloadParameters.nonSelectivelyDisclosable().setFamilyName("Doe"); // "family_name"

            // Custom claim
            payloadParameters.selectivelyDisclosable().addClaim(SDJWTClaim.create("company", "CompanyName"));

            // Custom Array claim
            SDJWTClaimArray pets = SDJWTClaim.createArray("pets");
            pets.addElement(SDJWTClaim.createSelectivelyDisclosable("dog"));
            pets.addElement(SDJWTClaim.createSelectivelyDisclosable("cat"));
            payloadParameters.selectivelyDisclosable().addClaim(pets);

            // Custom Object claim
            SDJWTClaimObject father = SDJWTClaim.createObject("father");
            father.addChild(SDJWTClaim.create("given_name", "Ben")); // Non SD child claim
            father.addChild(SDJWTClaim.create("family_name", "Doe")); // Non SD child claim
            SDJWTClaimArray nationalities = SDJWTClaim.createArraySelectivelyDisclosable("nationalities"); // SD child claim array
            nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("FR")); // SD child element
            nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("LU")); // SD child element
            father.addChild(nationalities);
            payloadParameters.nonSelectivelyDisclosable().addClaim(father);
            // end::sdjwt-payload-parameters[]

            // tag::sdjwt-signed-attestation[]
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
            // import eu.europa.esig.dss.jades.JAdESSignatureParameters;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

            // Configure signature parameters
            JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());
            signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

            // Set up the attestation service
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            SDJWTService service = new SDJWTService(commonCertificateVerifier);

            // Sign the attestation payload
            ToBeSigned dataToSign = service.getDataToBeSigned(payloadParameters, signatureParameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedAttestation = service.signAttestation(payloadParameters, signatureParameters, signatureValue);
            // end::sdjwt-signed-attestation[]

            // tag::sdjwt-get-disclosures[]
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;

            // Retrieve disclosures for the selectively disclosable claims
            List<SDJWTSelectiveDisclosure> disclosures = service.getDisclosures(payloadParameters);
            // end::sdjwt-get-disclosures[]

            // tag::sdjwt-key-binding[]
            // import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTKeyBindingParameters;
            // import eu.europa.esig.dss.jades.JAdESSignatureParameters;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;

            // Configure the key binding parameters
            SDJWTKeyBindingParameters keyBindingParameters = new SDJWTKeyBindingParameters();
            // "iat"
            keyBindingParameters.setIssuanceTime(new Date());
            // "aud"
            keyBindingParameters.setAudience("https://verifier.example.org");
            // "nonce"
            keyBindingParameters.setNonce("nonce-value-from-verifier");

            // Configure key binding signature parameters
            JAdESSignatureParameters kbSignatureParameters = new JAdESSignatureParameters();
            kbSignatureParameters.setSigningCertificate(deviceCertificate);
            kbSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
            kbSignatureParameters.setIncludeKeyIdentifier(false);
            kbSignatureParameters.setIncludeCertificateChain(false);

            // Sign the key binding JWT
            ToBeSigned kbDataToSign = service.getDataToSignForKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters);
            SignatureValue kbSignatureValue = signingToken.sign(kbDataToSign, kbSignatureParameters.getDigestAlgorithm(), devicePrivateKey);
            DSSDocument keyBindingJWT = service.createKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters, kbSignatureValue);
            // end::sdjwt-key-binding[]

            // tag::sdjwt-issuance[]
            // Issue a presentation with disclosures only
            DSSDocument presentationWithDisclosures = service.issuePresentation(signedAttestation, disclosures);

            // Issue a presentation with a key binding signature only
            DSSDocument presentationWithKB = service.issuePresentation(signedAttestation, keyBindingJWT);

            // Issue a presentation with both disclosures and a key binding signature
            DSSDocument presentationWithKBAndDisclosures = service.issuePresentation(signedAttestation, disclosures, keyBindingJWT);
            // end::sdjwt-issuance[]
        }
    }

    @Test
    void createMdoc() {
        // For mdoc, an ECDSA or EdDSA signing key is required
        try (SignatureTokenConnection signingToken = new CertEntitySignatureTokenConnection(getCertEntity(ECDSA_USER))) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // The device key is the holder's key used for device authentication
            DSSPrivateKeyEntry devicePrivateKey = signingToken.getKeys().get(0);
            CertificateToken deviceCertificate = devicePrivateKey.getCertificate();

            // tag::mdoc-payload-parameters[]
            // import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
            // import eu.europa.esig.dss.attestation.mdoc.creation.MdocPayloadParameters;

            MdocPayloadParameters payloadParameters = new MdocPayloadParameters();

            // docType is optional - auto-derived from configured claims if absent
            payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);

            // Device key for mdoc holder binding (set in the MSO)
            payloadParameters.setDeviceKey(deviceCertificate);

            // Configuration of known claims (automatically placed in the matching namespace)
            payloadParameters.selectivelyDisclosable().setGivenName("John");
            payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
            payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");
            payloadParameters.selectivelyDisclosable().setIssuingAuthority("TEST Authority");
            payloadParameters.selectivelyDisclosable().setDocumentNumber("123456789");

            // Custom claim with explicit namespace and element identifier
            payloadParameters.selectivelyDisclosable().addClaim("org.iso.23220.1", "custom_field", "custom_value");
            // end::mdoc-payload-parameters[]

            // tag::mdoc-status-list[]
            // IETF draft-ietf-oauth-revocation-list: index + URL
            payloadParameters.setStatusList(42, "https://example.com/statuslists/1");

            // ISO/IEC 18013-5 Identifier List: identifier bytes + URL
            payloadParameters.setIdentifierList(new byte[]{0x01, 0x02}, "https://example.com/identifierlists/1");
            // end::mdoc-status-list[]

            // reset for the rest of the test (only one revocation reference at a time in practice)
            payloadParameters.setStatusList((TokenStatusList) null);
            payloadParameters.setIdentifierList(null);

            // tag::mdoc-signed-attestation[]
            // import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
            // import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
            // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

            // Configure signature parameters (ECDSA or EdDSA required)
            CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
            signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            // Set up the attestation service
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            MdocService service = new MdocService(commonCertificateVerifier);

            // Sign the MSO (MobileSecurityObject) payload
            ToBeSigned dataToSign = service.getDataToBeSigned(payloadParameters, signatureParameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedAttestation = service.signAttestation(payloadParameters, signatureParameters, signatureValue);
            // end::mdoc-signed-attestation[]

            // tag::mdoc-get-disclosures[]
            // import eu.europa.esig.dss.attestation.mdoc.creation.MdocDisclosure;

            // Retrieve disclosures (one IssuerSignedItem per selectively disclosable element)
            List<MdocSelectiveDisclosure> disclosures = service.getDisclosures(payloadParameters);
            // end::mdoc-get-disclosures[]

            // tag::mdoc-key-binding[]
            // import eu.europa.esig.dss.attestation.mdoc.creation.MdocKeyBindingParameters;
            // import eu.europa.esig.dss.attestation.mdoc.creation.SessionTranscriptBuilder;
            // import eu.europa.esig.dss.enumerations.EllipticCurve;

            // Build the SessionTranscript (NFC Handover example)
            DSSDocument sessionTranscript = SessionTranscriptBuilder
                    .nfcHandover(new byte[]{0x01, 0x02}, new byte[]{0x03, 0x04})
                    .security(EllipticCurve.P_256, deviceCertificate.getPublicKey())
                    .eReaderKey(deviceCertificate.getPublicKey())
                    .build();

            // Configure the key binding parameters
            MdocKeyBindingParameters keyBindingParameters = new MdocKeyBindingParameters();
            keyBindingParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
            keyBindingParameters.setSessionTranscript(sessionTranscript);

            // Key binding signature parameters (DETACHED, no certificate chain)
            CBAdESSignatureParameters kbSignatureParameters = new CBAdESSignatureParameters();
            kbSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            kbSignatureParameters.setSigningCertificate(deviceCertificate);

            // Sign the DeviceAuthentication structure
            ToBeSigned kbDataToSign = service.getDataToSignForKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters);
            SignatureValue kbSignatureValue = signingToken.sign(kbDataToSign, kbSignatureParameters.getDigestAlgorithm(), devicePrivateKey);
            DSSDocument deviceAuthSignature = service.createKeyBindingSignature(signedAttestation, disclosures, keyBindingParameters, kbSignatureParameters, kbSignatureValue);
            // end::mdoc-key-binding[]

            // tag::mdoc-issuance[]
            // Issue an IssuerSigned document (CBOR, no device authentication)
            DSSDocument issuerSigned = service.createIssuerSigned(signedAttestation, disclosures);

            // Issue a full DeviceResponse (CBOR, with device authentication)
            DSSDocument deviceResponse = service.issuePresentation(signedAttestation, disclosures, deviceAuthSignature);
            // end::mdoc-issuance[]
        }
    }
}
