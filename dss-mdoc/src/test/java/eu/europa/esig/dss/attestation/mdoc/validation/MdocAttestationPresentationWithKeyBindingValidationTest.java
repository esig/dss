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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.common.key.DefaultPublicKeyInfoFactory;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;
import eu.europa.esig.dss.attestation.mdoc.creation.SessionTranscriptBuilder;
import eu.europa.esig.dss.attestation.mdoc.key.COSEKeyBuilder;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.fail;

class MdocAttestationPresentationWithKeyBindingValidationTest extends AbstractMdocAttestationPresentationTestValidation {

    private static DSSDocument originalDocument;

    private String signer;

    @Override
    protected DSSDocument getSignedDocument() {

        CBORValue.CBORMapEditor mobileSecurityObjectEditor = CBOR.map();
        mobileSecurityObjectEditor.put("version", "1.0");
        mobileSecurityObjectEditor.put("digestAlgorithm", DigestAlgorithm.SHA256.getMSOId());
        CBORValue valueDigests = CBOR.map()
                .put("org.iso.18013.5.1", getDigestIDs(1L, DSSUtils.digest(DigestAlgorithm.SHA256, "Hello World".getBytes())))
                .value();
        mobileSecurityObjectEditor.put("valueDigests", valueDigests);
        mobileSecurityObjectEditor.put("deviceKeyInfo", getDeviceKeyInfo());
        mobileSecurityObjectEditor.put("docType", "org.iso.18013.5.1.mDL");

        Calendar calendar = Calendar.getInstance();

        CBORValue.CBORMapEditor validityInfo = CBOR.map();
        Date signed = calendar.getTime();
        validityInfo.put("signed", CBORTags.tdate(signed));
        validityInfo.put("validFrom", CBORTags.tdate(signed));
        calendar.add(Calendar.HOUR, 1);
        validityInfo.put("validUntil", CBORTags.tdate(calendar.getTime()));

        mobileSecurityObjectEditor.put("validityInfo", validityInfo.value());

        CBORValue mobileSecurityObjectBytes = CBORTags.encodedCbor(mobileSecurityObjectEditor.value().encodeToBytes());
        originalDocument = new InMemoryDocument(CBORUtils.serializeCbor(mobileSecurityObjectBytes));

        signer = GOOD_USER;

        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setTagged(false);

        CBAdESService service = new CBAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(originalDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(originalDocument, signatureParameters, signatureValue);

        CBORValue.CBORMapEditor mdocResponse = CBOR.map();
        mdocResponse.put("version", "1.0");

        CBORValue.CBORArrayEditor documents = CBOR.array();
        CBORValue.CBORMapEditor document = CBOR.map();
        String docType = "org.iso.18013.5.1.mDL";
        document.put("docType", docType);

        CBORValue issuerSigned = CBOR.map()
                .put("issuerAuth", toCbor(signedDocument))
                .value();
        document.put("issuerSigned", issuerSigned);

        CBORValue.CBORMapEditor deviceSigned = CBOR.map();
        CBORValue deviceSignedNameSpaces = CBORTags.encodedCbor(CBOR.map().value().encodeToBytes());
        deviceSigned.put("nameSpaces", deviceSignedNameSpaces); // empty

        signer = ECDSA_USER;

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSigDMechanism(SigDMechanism.NO_SIG_D);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setTagged(false);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setIncludeKeyIdentifier(false);

        CBORValue sessionTranscript = buildSessionTranscript();
        DSSDocument deviceAuthenticationBytes = buildDeviceAuthenticationBytes(sessionTranscript, docType, deviceSignedNameSpaces);

        service = new CBAdESService(getOfflineCertificateVerifier());
        dataToSign = service.getDataToSign(deviceAuthenticationBytes, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument keyBindingSignature = service.signDocument(deviceAuthenticationBytes, signatureParameters, signatureValue);

        CBORValue deviceAuth = CBOR.map()
                .put("deviceSignature", toCbor(keyBindingSignature))
                .value();
        deviceSigned.put("deviceAuth", deviceAuth);
        document.put("deviceSigned", deviceSigned.value());

        documents.add(document.value());
        mdocResponse.put("documents", documents.value());
        mdocResponse.put("status", 0L);

        // embed in mdoc
        DSSDocument mdocDocument = new InMemoryDocument(CBORUtils.serializeCbor(mdocResponse.value()));
        return mdocDocument;
    }

    @Override
    protected DSSDocument getSessionTranscript() {
        return new InMemoryDocument(CBORUtils.serializeCbor(buildSessionTranscript()));
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        // skip
    }

    @Override
    protected boolean orphanSelectiveDisclosuresPresent() {
        return true;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return signer;
    }

    private CBORValue getDeviceKeyInfo() {
        signer = ECDSA_USER;
        PublicKeyInfo publicKeyInfo = new DefaultPublicKeyInfoFactory().create(getSigningCert().getPublicKey());
        CBORValue coseKey = new COSEKeyBuilder(publicKeyInfo).create();
        return CBOR.map()
                .put("deviceKey", coseKey)
                .value();
    }

    private DSSDocument buildDeviceAuthenticationBytes(CBORValue sessionTranscript, String docType, CBORValue deviceNameSpaceBytes) {
        CBORValue deviceAuthentication = CBOR.array()
                .add("DeviceAuthentication")
                .add(sessionTranscript)
                .add(docType)
                .add(deviceNameSpaceBytes)
                .value();
        CBORValue deviceAuthenticationBytes = CBORTags.encodedCbor(deviceAuthentication.encodeToBytes());
        return new InMemoryDocument(CBORUtils.serializeCbor(deviceAuthenticationBytes));
    }

    private CBORValue buildSessionTranscript() {
        signer = ECDSA_USER;

        return SessionTranscriptBuilder.nfcHandover(
                    Utils.fromHex("91020F487315D10209616301013001046D646F631A200C016170706C69636174696F6E2F766E642E626C7565746F6F74682E6C652E6F6F6230081B28128B37282801021C015C1E580469736F2E6F72673A31383031333A646576696365656E676167656D656E746D646F63A20063312E30018201D818584BA4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67"),
                    Utils.fromHex("91022548721591020263720102110204616301013000110206616301036E6663005102046163010157001A201E016170706C69636174696F6E2F766E642E626C7565746F6F74682E6C652E6F6F6230081B28078080BF2801021C021107C832FFF6D26FA0BEB34DFCD555D4823A1C11010369736F2E6F72673A31383031333A6E66636E6663015A172B016170706C69636174696F6E2F766E642E7766612E6E616E57030101032302001324FEC9A70B97AC9684A4E326176EF5B981C5E8533E5F00298CFCCBC35E700A6B020414")
                )
                .security(EllipticCurve.P_256, getSigningCert().getPublicKey())
                .eReaderKey(getSigningCert().getPublicKey())
                .buildCbor();
    }

    private CBORValue toCbor(DSSDocument document) {
        try {
            return CBORUtils.parseCbor(document);
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private CBORValue getDigestIDs(Long id, byte[] digest) {
        return CBOR.map()
                .put(id, CBOR.bytes(digest))
                .value();
    }

}
