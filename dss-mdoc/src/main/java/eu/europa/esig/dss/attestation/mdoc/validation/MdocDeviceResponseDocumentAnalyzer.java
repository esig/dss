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

import co.nstant.in.cbor.CborException;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.MdocDeviceResponseParser;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceAuth;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceNameSpaces;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceResponse;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceSigned;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDocument;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.attestation.SelectivelyDisclosableClaim;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class is used to parse and process attestations embedded within an mdoc DeviceResponse structure
 *
 */
public class MdocDeviceResponseDocumentAnalyzer extends AbstractMdocDocumentAnalyzer {

    private static final Logger LOG = LoggerFactory.getLogger(MdocDeviceResponseDocumentAnalyzer.class);

    /** Cached instance of the mdoc */
    private MdocDeviceResponse mdoc;

    /**
     * Default constructor
     */
    public MdocDeviceResponseDocumentAnalyzer() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to validate
     */
    public MdocDeviceResponseDocumentAnalyzer(DSSDocument document) {
        super(document);
        this.mdoc = buildMdoc();
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new MdocDeviceResponseParser(document).isSupported();
    }

    private MdocDeviceResponse buildMdoc() {
        return new MdocDeviceResponseParser(document).parse();
    }

    @Override
    protected MdocAttestationPresentation buildAttestationPresentation() {
        MdocAttestationPresentation attestationPresentation = new MdocAttestationPresentation();
        attestationPresentation.setAttestationPresentationType(AttestationDocumentFormat.MDOC_DEVICE_RESPONSE);
        attestationPresentation.setMdocDeviceResponse(mdoc);

        final List<Attestation> attestations = new ArrayList<>();
        for (MdocDocument mdocDocument : mdoc.getDocuments()) {
            MdocAttestation mdocAttestation = MdocAttestation.initBuilder()
                    .setSignatures(Collections.singletonList(getSignature(mdocDocument.getIssuerSigned())))
                    .setDisclosures(getSignedItems(mdocDocument.getIssuerSigned()))
                    .setKeyBindingSignature(getKeyBindingSignature(mdocDocument.getDeviceSigned(), mdocDocument.getDocType(), mdocDocument.getDeviceSigned().getDeviceNameSpaces()))
                    .setFilename(document.getName())
                    .setDocument(mdocDocument)
                    .build();
            attestations.add(mdocAttestation);
        }
        attestationPresentation.setElectronicAttestationsOfAttributes(attestations);

        return attestationPresentation;
    }

    /**
     * Gets a list of signatures extracted from an 'issuerSigned'/'issuerAuth' header of a Document object.
     * NOTE: The ISO 18013-5 specifies that a COSE_Sign1 structure shall be used, thus only one signature is expected.
     *
     * @param issuerSigned {@link MdocIssuerSigned}
     * @return {@link CBAdESSignature}
     */
    protected CBAdESSignature getSignature(MdocIssuerSigned issuerSigned) {
        return new MdocIssuerSignedDocumentAnalyzer(document, issuerSigned).getSignature();
    }

    /**
     * Returns a list of disclosures extracted for every namespace from a Document structure
     *
     * @param issuerSigned {@link MdocIssuerSigned}
     * @return a list of {@link SelectivelyDisclosableClaim}s
     */
    protected List<SelectivelyDisclosableClaim> getSignedItems(MdocIssuerSigned issuerSigned) {
        return new MdocIssuerSignedDocumentAnalyzer(document, issuerSigned).getSignedItems();
    }

    /**
     * Gets a keyBinding signature embedded within a 'deviceSigned'/'deviceAuth' header
     *
     * @param deviceSigned {@link MdocDeviceSigned}
     * @param docType {@link String}
     * @param deviceNameSpaces {@link MdocDeviceNameSpaces}
     * @return {@link AdvancedSignature}
     */
    protected AdvancedSignature getKeyBindingSignature(MdocDeviceSigned deviceSigned, String docType, MdocDeviceNameSpaces deviceNameSpaces) {
        // TODO : support namespaces extraction for a key binding signature ?
        MdocDeviceAuth deviceAuth = deviceSigned.getDeviceAuth();
        if (deviceAuth.getDeviceSignature() != null) {
            CBAdESSignature signature = getCoseSignature(deviceAuth.getDeviceSignature());
            signature.setDetachedContents(Collections.singletonList(getDeviceAuthenticationBytes(docType, deviceNameSpaces)));
            return signature;

        } else if (deviceAuth.getDeviceMac() != null) {
            LOG.warn("The 'deviceMac' is not supported by the implementation. " +
                    "The processing of key binding signature will be skipped.");
        } else {
            LOG.warn("No supported key binding signature found within the mdoc Document entry. " +
                    "The processing of key binding signature will be skipped.");
        }
        return null;
    }

    /**
     * Build a DeviceAuthenticationBytes object as defined in ISO 18013-5
     *
     * @param docType {@link String}
     * @param deviceNameSpaces {@link MdocDeviceNameSpaces}
     * @return {@link DSSDocument}
     */
    protected DSSDocument getDeviceAuthenticationBytes(String docType, MdocDeviceNameSpaces deviceNameSpaces) {
        MdocValidationParameters attestationValidationParameters = getAttestationValidationParameters();
        if (attestationValidationParameters == null) {
            LOG.info("No validation parameters have been provided. Required for a key binding signature validation. " +
                    "Absence will result to invalidity of the key binding signature.");
            return null;
        }
        DSSDocument sessionTranscript = attestationValidationParameters.getSessionTranscript();
        if (sessionTranscript == null) {
            LOG.info("No session transcript bytes have been provided. Validation of key binding signature is limited.");
            return null;
        }

        /*
         * ISO 18013-5 "9.1.3.4 Mechanism (mdoc authentication)"
         *
         * DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
         * DeviceAuthentication = [
         *     "DeviceAuthentication",
         *     SessionTranscript,
         *     DocType,                    ; Same as in mdoc response
         *     DeviceNameSpacesBytes       ; Same as in mdoc response
         * ]
         */
        final CBORArray deviceAuthentication = new CBORArray();
        deviceAuthentication.add(MdocConstants.DEVICE_AUTHENTICATION);

        CBORArray sessionTranscriptCbor = new CBORArray();
        try {
            CBORObject cborObject = CBORUtils.parseCbor(sessionTranscript);
            if (cborObject.isArray()) {
                sessionTranscriptCbor = (CBORArray) cborObject;
            } else if (cborObject.isByteString()) {
                cborObject = CBORUtils.parseCbor(cborObject.getValueAsBytes());
                if (cborObject.isArray()) {
                    sessionTranscriptCbor = (CBORArray) cborObject;
                } else {
                    LOG.warn("Session transcript binaries do not represent a CBOR array. Obtained type : {}", cborObject.getClass().getSimpleName());
                }
            } else {
                LOG.warn("Session transcript is expected in a form of a CBOR array or binaries. Obtained type : {}", cborObject.getClass().getSimpleName());
            }

        } catch (CborException e) {
            LOG.warn("Unable to parse session transcript as CBOR object : {}", e.getMessage(), e);
        }
        deviceAuthentication.add(sessionTranscriptCbor);
        deviceAuthentication.add(docType);
        deviceAuthentication.add(deviceNameSpaces.getDeviceNameSpaceBytes());

        CBORByteString deviceAuthenticationBytes = CBORUtils.toCborBtsrWrappedTagged(deviceAuthentication);
        return new InMemoryDocument(CBORUtils.serializeCborObject(deviceAuthenticationBytes));
    }

}
