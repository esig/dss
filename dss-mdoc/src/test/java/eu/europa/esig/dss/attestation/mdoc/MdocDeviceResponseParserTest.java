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
package eu.europa.esig.dss.attestation.mdoc;

import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceAuth;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceNameSpaces;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceResponse;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceSigned;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDocument;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocDeviceResponseParserTest {

    @Test
    void iso180135MdocResponseSample() {
        DSSDocument mdocDocument = new FileDocument("src/test/resources/validation/mdocResponseIso180135.mdoc");

        MdocDeviceResponseParser mdocParser = new MdocDeviceResponseParser(mdocDocument);
        assertTrue(mdocParser.isSupported());

        MdocDeviceResponse deviceResponse = mdocParser.parse();
        assertNotNull(deviceResponse);

        assertEquals("1.0", deviceResponse.getVersion());
        List<MdocDocument> documents = deviceResponse.getDocuments();
        assertEquals(1, documents.size());

        MdocDocument document = documents.get(0);
        assertEquals("org.iso.18013.5.1.mDL", document.getDocType());

        MdocIssuerSigned issuerSigned = document.getIssuerSigned();
        assertNotNull(issuerSigned);

        Map<String, List<MdocIssuerSignedItem>> namespaces = issuerSigned.getNamespaces();
        assertEquals(1, namespaces.size());

        Map.Entry<String, List<MdocIssuerSignedItem>> namespacesEntry = namespaces.entrySet().iterator().next();
        assertEquals("org.iso.18013.5.1", namespacesEntry.getKey());
        assertEquals(6, namespacesEntry.getValue().size());

        COSESignStructure issuerAuth = issuerSigned.getIssuerAuth();
        assertNotNull(issuerAuth);
        assertEquals(COSESignatureType.COSE_SIGN1, issuerAuth.getContext());

        MdocDeviceSigned deviceSigned = document.getDeviceSigned();
        assertNotNull(deviceSigned);

        MdocDeviceNameSpaces deviceNameSpaces = deviceSigned.getDeviceNameSpaces();
        assertNotNull(deviceNameSpaces);
        assertTrue(Utils.isMapEmpty(deviceNameSpaces.getNamespaces()));

        MdocDeviceAuth deviceAuth = deviceSigned.getDeviceAuth();
        assertNotNull(deviceAuth);
        assertNull(deviceAuth.getDeviceSignature());
        assertNotNull(deviceAuth.getDeviceMac());

        assertTrue(Utils.isMapEmpty(document.getErrors()));
        assertTrue(Utils.isCollectionEmpty(deviceResponse.getDocumentErrors()));

        assertEquals(0, deviceResponse.getStatus());

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESignStructure(issuerAuth);
        assertEquals(1, cborSignatures.size());

        CBORSignature cose = cborSignatures.get(0);

        CBORObject x5chain = cose.getUnprotectedHeaderValue(CBORObjectFactory.toCBORObject(33L));
        assertTrue(x5chain.isByteString());

        CertificateToken certificateToken = DSSUtils.loadCertificate(x5chain.getValueAsBytes());
        assertNotNull(certificateToken);

        cose.setKey(certificateToken.getPublicKey());
        assertTrue(cose.verifySignature());
    }

}
