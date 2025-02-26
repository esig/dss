/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.tsl.TLStructureVerifier;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TLStructureVerifierTest {

    private static final List<Integer> DEFAULT_ACCEPTED_TL_VERSION = Arrays.asList(5, 6);

    @Test
    void tlv4Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/de-tl.xml");

        TLStructureVerifier tlStructureVerifier = new TLStructureVerifier();
        List<String> result = tlStructureVerifier.validate(tlDocument, 4);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 4);
        assertTrue(result.stream().anyMatch(r -> r.contains("The TL Version '4' is not acceptable!")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 6);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 6);
        assertFalse(result.stream().anyMatch(r -> r.contains("The ds:Signature element shall not be present for XML Trusted List signing!")));
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).setSigningMode(true).validate(tlDocument, 6);
        assertTrue(result.stream().anyMatch(r -> r.contains("The ds:Signature element shall not be present for XML Trusted List signing!")));
        assertFalse(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).setSigningMode(false).validate(tlDocument, 6);
        assertFalse(result.stream().anyMatch(r -> r.contains("The ds:Signature element shall not be present for XML Trusted List signing!")));
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

    @Test
    void tlv5Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/fr.xml");

        TLStructureVerifier tlStructureVerifier = new TLStructureVerifier();
        List<String> result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 6);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 6);
        assertFalse(result.stream().anyMatch(r -> r.contains("The ds:Signature element shall not be present for XML Trusted List signing!")));
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).setSigningMode(true).validate(tlDocument, 6);
        assertTrue(result.stream().anyMatch(r -> r.contains("The ds:Signature element shall not be present for XML Trusted List signing!")));
        assertFalse(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).setSigningMode(false).validate(tlDocument, 6);
        assertFalse(result.stream().anyMatch(r -> r.contains("The ds:Signature element shall not be present for XML Trusted List signing!")));
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 4);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 4);
        assertTrue(result.stream().anyMatch(r -> r.contains("The TL Version '4' is not acceptable!")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

    @Test
    void tlv6Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/fi-v6.xml");

        TLStructureVerifier tlStructureVerifier = new TLStructureVerifier();
        List<String> result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 6);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 5);
        assertTrue(result.stream().anyMatch(r -> r.contains("ServiceSupplyPoint")));
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificateV2")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 4);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 4);
        assertTrue(result.stream().anyMatch(r -> r.contains("The TL Version '4' is not acceptable!")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

}
