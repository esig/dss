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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.mdoc.IssuerSignedParser;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.MdocHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Builds an Attestation Presentation based on the ISO/IEC 18013-5 mdoc format
 * 
 */
public class MdocPresentationBuilder {

    /**
     * Empty constructor
     */
    public MdocPresentationBuilder() {
        //empty
    }

    /**
     * Builds a DSSDocument representing the IssuerSigned structure as defined in "8.3.2.1.2.2 Device retrieval mdoc response"
     *
     * @param attestation {@link DSSDocument} containing the signed attestation
     * @param disclosures a list of {@link MdocIssuerSignedItem}s to be included
     * @return {@link DSSDocument}
     */
    public DSSDocument buildIssuerSignedDocument(DSSDocument attestation, List<MdocIssuerSignedItem> disclosures) {
        CBORValue issuerSigned = buildIssuerSigned(attestation, disclosures);
        return new InMemoryDocument(issuerSigned.encodeToBytes());
    }

    /**
     * Builds a CBORMap representing the IssuerSigned structure as defined in "8.3.2.1.2.2 Device retrieval mdoc response".
     * {@code
     *   IssuerSigned = {
     *     ? "nameSpaces" : IssuerNameSpaces,  ; Returned data elements
     *     "issuerAuth" : IssuerAuth           ; Contains the mobile security object (MSO)
     *                                         ; for issuer data authentication
     *   }
     * }
     *
     * @param attestation {@link DSSDocument} containing the attestation signature (IssuerAuth)
     * @param disclosures a list of {@link MdocIssuerSignedItem}s to be included
     * @return {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue}
     */
    protected CBORValue buildIssuerSigned(DSSDocument attestation, List<MdocIssuerSignedItem> disclosures) {
        Objects.requireNonNull(attestation, "Attestation cannot be null!");
        if (!CBORUtils.isCbor(attestation)) {
            throw new IllegalInputException("Attestation document shall represent a CBOR encoded object!");
        }

        try {
            // TODO : do verification in a separate method ?
            CBORValue issuerAuth = CBORUtils.parseCbor(attestation);

            final CBORValue.CBORMapEditor issuerSigned = CBOR.map();
            if (Utils.isCollectionNotEmpty(disclosures)) {
                issuerSigned.put(MdocConstants.NAMESPACES, buildIssuerNameSpaces(disclosures));
            }
            issuerSigned.put(MdocHeaderParameter.ISSUER_AUTH.toString(), issuerAuth);
            return issuerSigned.value();

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to build IssuerSigned. Reason : %s", e.getMessage()), e);
        }

    }

    /**
     * Builds a CBORMap representing the IssuerNameSpaces structure as defined in "8.3.2.1.2.2 Device retrieval mdoc response".
     * {@code
     *   IssuerNameSpaces = {                  ; Returned data elements for each namespace
     *     + NameSpace => [ + IssuerSignedItemBytes ]
     *   }
     * }
     *
     * @param disclosures a list of {@link MdocIssuerSignedItem}s to be included
     * @return {@link CBORValue}
     */
    protected CBORValue buildIssuerNameSpaces(List<MdocIssuerSignedItem> disclosures) {
        final CBORValue.CBORMapEditor issuerNameSpaces = CBOR.map();
        Map<String, List<CBORValue>> issuerSignedBytesByNamespace = disclosures.stream().collect(
                Collectors.groupingBy(MdocIssuerSignedItem::getNamespace, LinkedHashMap::new,
                        Collectors.mapping(MdocIssuerSignedItem::getIssuerSignedItemBytes, Collectors.toList())));
        issuerSignedBytesByNamespace.forEach((k, v) -> issuerNameSpaces.put(k, CBOR.array(v).value()));
        return issuerNameSpaces.value();
    }

    /**
     * Builds a DeviceResponse structure
     *
     * @param attestation {@link DSSDocument}
     * @param disclosures a list of {@link MdocIssuerSignedItem}s
     * @param keyBinding {@link DSSDocument}
     * @param deviceSignedParameters {@link MdocDeviceSignedParameters}
     * @return {@link DSSDocument} DeviceResponse structure
     */
    public DSSDocument buildDeviceResponseDocument(DSSDocument attestation, List<MdocIssuerSignedItem> disclosures,
                                                   DSSDocument keyBinding, MdocDeviceSignedParameters deviceSignedParameters) {
        try {
            CBORValue issuerSigned = buildIssuerSigned(attestation, disclosures);
            CBORValue deviceSignature = CBORUtils.parseCbor(keyBinding);

            CBORValue deviceAuth = CBOR.map()
                    .put(MdocHeaderParameter.DEVICE_SIGNATURE.toString(), deviceSignature)
                    .value();

            CBORValue deviceSigned = CBOR.map()
                    .put(MdocHeaderParameter.NAMESPACES.toString(), getDeviceNameSpacesBuilder().buildDeviceNameSpacesBytes(deviceSignedParameters))
                    .put(MdocHeaderParameter.DEVICE_AUTH.toString(), deviceAuth)
                    .value();

            CBORValue document = CBOR.map()
                    .put(MdocHeaderParameter.DOC_TYPE.toString(), extractDocTypeFromIssuerSigned(issuerSigned))
                    .put(MdocHeaderParameter.ISSUER_SIGNED.toString(), issuerSigned)
                    .put(MdocHeaderParameter.DEVICE_SIGNED.toString(), deviceSigned)
                    .value();

            CBORValue documents = CBOR.array()
                    .add(document)
                    .value();

            CBORValue deviceResponse = CBOR.map()
                    .put(MdocHeaderParameter.VERSION.toString(), CBOR.text("1.0"))
                    .put(MdocHeaderParameter.DOCUMENTS.toString(), documents)
                    .put(MdocHeaderParameter.STATUS.toString(), CBOR.integer(0))
                    .value();

            return new InMemoryDocument(CBORUtils.serializeCbor(deviceResponse));

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to issue presentation. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Builds a DeviceAuthentication structure, representing a payload of a key binding signature
     *
     * @param keyBindingParameters {@link MdocKeyBindingParameters}
     * @return {@link DSSDocument}
     */
    public DSSDocument buildDeviceAuthentication(final MdocKeyBindingParameters keyBindingParameters) {
        return getDeviceAuthenticationBuilder().build(keyBindingParameters);
    }

    /**
     * Gets the builder to use to build the DeviceAuthentication structure
     *
     * @return {@link MdocDeviceAuthenticationBuilder}
     */
    protected MdocDeviceAuthenticationBuilder getDeviceAuthenticationBuilder() {
        return new DefaultMdocDeviceAuthenticationBuilder();
    }

    /**
     * Gets the builder to use to build the DeviceNameSpacesBytes
     *
     * @return {@link MdocDeviceNameSpacesBuilder}
     */
    protected MdocDeviceNameSpacesBuilder getDeviceNameSpacesBuilder() {
        return new DefaultMdocDeviceNameSpacesBuilder();
    }

    /**
     * Extract the value of the docType from the issuerSigned to use it in the DeviceResponse
     *
     * @param issuerSigned the issuerSigned
     * @return {@link String} the value of the docType
     * @deprecated since DSS 6.6. Use {@link #extractDocTypeFromIssuerSigned(CBORValue)}.
     */
    @Deprecated
    protected String extractDocTypeFromIssuerSigned(final CBORMap issuerSigned) {
        return extractDocTypeFromIssuerSigned(issuerSigned.toCBORValue());
    }

    /**
     * Extract the value of the docType from the issuerSigned to use it in the DeviceResponse
     *
     * @param issuerSigned the issuerSigned
     * @return {@link String} the value of the docType
     */
    protected String extractDocTypeFromIssuerSigned(final CBORValue issuerSigned) {
        IssuerSignedParser parser = new IssuerSignedParser(issuerSigned);
        CBORValue encodedPayload = parser.parse().getIssuerAuth().getPayload();
        CBORValue mobileSecurityObjectBytes = CBORUtils.parseCbor(encodedPayload.asBytes());
        if (!mobileSecurityObjectBytes.isTag() || CBORTags.ENCODED_CBOR != mobileSecurityObjectBytes.getTag().longValue()) {
            throw new IllegalInputException("IssuerAuth payload shall be of MobileSecurityObjectBytes type!");
        }
        CBORValue decodedPayload = mobileSecurityObjectBytes.getTaggedValue();
        if (!decodedPayload.isByteString()) {
            throw new IllegalInputException("MobileSecurityObjectBytes tagged value shall be of CBOR Byte String type!");
        }
        CBORValue mobileSecurityObject = CBORUtils.parseCbor(decodedPayload.asBytes());
        if (!mobileSecurityObject.isMap()) {
            throw new IllegalInputException("MobileSecurityObject shall be of CBOR Map type!");
        }
        return mobileSecurityObject.getAsStringOrNull(MdocConstants.DOC_TYPE);
    }

}
