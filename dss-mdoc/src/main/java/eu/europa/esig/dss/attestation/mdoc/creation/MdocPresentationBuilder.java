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

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.attestation.mdoc.IssuerSignedParser;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.MdocHeaderParameter;
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
     * @param disclosures a list of {@link MdocSelectiveDisclosure}s to be included
     * @return {@link DSSDocument}
     */
    public DSSDocument buildIssuerSignedDocument(DSSDocument attestation, List<MdocSelectiveDisclosure> disclosures) {
        CBORMap issuerSigned = buildIssuerSigned(attestation, disclosures);
        return new InMemoryDocument(CBORUtils.serializeCborObject(issuerSigned));
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
     * @param disclosures a list of {@link MdocSelectiveDisclosure}s to be included
     * @return {@link CBORMap}
     */
    protected CBORMap buildIssuerSigned(DSSDocument attestation, List<MdocSelectiveDisclosure> disclosures) {
        Objects.requireNonNull(attestation, "Attestation cannot be null!");
        if (!CBORUtils.isCbor(attestation)) {
            throw new IllegalInputException("Attestation document shall represent a CBOR encoded object!");
        }

        try {
            // TODO : do verification in another separate MdocService method ?
            CBORObject issuerAuth = CBORUtils.parseCbor(attestation);

            final CBORMap issuerSigned = new CBORMap();
            if (Utils.isCollectionNotEmpty(disclosures)) {
                issuerSigned.put(MdocConstants.NAMESPACES, buildIssuerNameSpaces(disclosures));
            }
            issuerSigned.put(MdocHeaderParameter.ISSUER_AUTH.toString(), issuerAuth);
            return issuerSigned;

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
     * @param disclosures a list of {@link MdocSelectiveDisclosure}s to be included
     * @return {@link CBORMap}
     */
    protected CBORMap buildIssuerNameSpaces(List<MdocSelectiveDisclosure> disclosures) {
        final CBORMap issuerNameSpaces = new CBORMap();
        Map<String, List<CBORByteString>> issuerSignedBytesByNamespace = disclosures.stream().collect(
                Collectors.groupingBy(MdocSelectiveDisclosure::getNamespace, LinkedHashMap::new,
                        Collectors.mapping(MdocSelectiveDisclosure::getIssuerSignedItemBytes, Collectors.toList())));
        issuerSignedBytesByNamespace.forEach((k, v) -> issuerNameSpaces.put(k, new CBORArray(v)));
        return issuerNameSpaces;
    }

    /**
     * Builds a DeviceResponse structure
     *
     * @param attestation {@link DSSDocument}
     * @param disclosures a list of {@link MdocSelectiveDisclosure}s
     * @param keyBinding {@link DSSDocument}
     * @param deviceSignedParameters {@link MdocDeviceSignedParameters}
     */
    public DSSDocument buildDeviceResponseDocument(DSSDocument attestation, List<MdocSelectiveDisclosure> disclosures,
                                                   DSSDocument keyBinding, MdocDeviceSignedParameters deviceSignedParameters) {
        try {
            CBORMap issuerSigned = buildIssuerSigned(attestation, disclosures);
            CBORObject deviceSignature = CBORUtils.parseCbor(keyBinding);

            CBORMap deviceAuth = new CBORMap();
            deviceAuth.put(MdocHeaderParameter.DEVICE_SIGNATURE.toString(), deviceSignature);

            CBORMap deviceSigned = new CBORMap();

            deviceSigned.put(MdocHeaderParameter.NAMESPACES.toString(), getDeviceNameSpacesBuilder().buildDeviceNameSpacesBytes(deviceSignedParameters));
            deviceSigned.put(MdocHeaderParameter.DEVICE_AUTH.toString(), deviceAuth);

            CBORMap document = new CBORMap();
            document.put(MdocHeaderParameter.DOC_TYPE.toString(), extractDocTypeFromIssuerSigned(issuerSigned));
            document.put(MdocHeaderParameter.ISSUER_SIGNED.toString(), issuerSigned);
            document.put(MdocHeaderParameter.DEVICE_SIGNED.toString(), deviceSigned);

            CBORArray documents =  new CBORArray();
            documents.add(document);

            CBORMap deviceResponse = new CBORMap();
            deviceResponse.put(MdocHeaderParameter.VERSION.toString(), CBORObjectFactory.toCBORObject("1.0"));
            deviceResponse.put(MdocHeaderParameter.DOCUMENTS.toString(), documents);
            deviceResponse.put(MdocHeaderParameter.STATUS.toString(), CBORObjectFactory.toCBORObject(0));

            return new InMemoryDocument(CBORUtils.serializeCborObject(deviceResponse));

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
     */
    protected String extractDocTypeFromIssuerSigned(final CBORMap issuerSigned) {
        IssuerSignedParser parser = new IssuerSignedParser(issuerSigned);
        CBORByteString encodedPayload = (CBORByteString) parser.parse().getIssuerAuth().getPayload();
        CBORByteString decodedPayload = (CBORByteString) CBORUtils.parseCbor(encodedPayload.getValueAsBytes());
        CBORMap mso = new CBORMap(decodedPayload);
        return mso.getAsString(MdocConstants.DOC_TYPE);
    }

}
