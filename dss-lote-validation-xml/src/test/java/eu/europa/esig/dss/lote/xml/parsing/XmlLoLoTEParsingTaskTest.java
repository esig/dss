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
package eu.europa.esig.dss.lote.xml.parsing;

import eu.europa.esig.dss.lote.parsing.LoLoTEParsingResult;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.lote.OtherListPointer;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class XmlLoLoTEParsingTaskTest {

    private static final String LOLOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUlistofthelists";

    @Test
    void testValid() {
        DSSDocument lote = new FileDocument("src/test/resources/lolote.xml");
        LoLoTESource loloteSource = new LoLoTESource();
        loloteSource.setLolotePredicate(otherListPointer ->
                LOLOTE_TYPE.equals(otherListPointer.getType()));
        loloteSource.setLotePredicate(otherListPointer ->
                !LOLOTE_TYPE.equals(otherListPointer.getType()));
        XmlLoLoTEParsingTask task = new XmlLoLoTEParsingTask(lote, loloteSource);
        LoLoTEParsingResult result = task.get();
        assertNotNull(result);
        assertEquals(1, result.getVersion());
        assertEquals(1, result.getSequenceNumber());
        assertNotNull(result.getIssueDate());
        assertNotNull(result.getNextUpdateDate());
        assertEquals("EU", result.getTerritory());
        assertFalse(Utils.isCollectionNotEmpty(result.getDistributionPoints()));
        assertFalse(Utils.isCollectionNotEmpty(result.getStructureValidationMessages()));

        assertEquals(1, result.getCurrentListPointers().size());
        checkOtherListPointers(result.getCurrentListPointers());
        assertEquals(1, result.getOtherListPointers().size());
        checkOtherListPointers(result.getOtherListPointers());

        OtherListPointer otherListPointer = result.getCurrentListPointers().get(0);
        assertEquals(1, otherListPointer.getSdiCertificates().size());
        assertEquals("https://test.test/lolote", otherListPointer.getLocationUrl());
        assertEquals("EU", otherListPointer.getSchemeTerritory());
        assertEquals("http://uri.etsi.org/19602/LoTEType/EUlistofthelists", otherListPointer.getType());
        assertEquals(2, otherListPointer.getSchemeOperatorNames().size());
        assertEquals("en", otherListPointer.getSchemeOperatorNames().keySet().iterator().next());
        assertEquals(1, otherListPointer.getSchemeOperatorNames().get("en").size());
        assertEquals("European Commission", otherListPointer.getSchemeOperatorNames().get("en").get(0));
        assertEquals(1, otherListPointer.getSchemeTypeCommunityRules().size());
        assertEquals("en", otherListPointer.getSchemeTypeCommunityRules().keySet().iterator().next());
        assertEquals(1, otherListPointer.getSchemeTypeCommunityRules().get("en").size());
        assertEquals("http://uri.etsi.org/19602/ListOfLists/schemerules/EU", otherListPointer.getSchemeTypeCommunityRules().get("en").get(0));

    }

    private void checkOtherListPointers(List<OtherListPointer> otherListPointers) {
        for (OtherListPointer otherListPointer : otherListPointers) {
            assertNotNull(otherListPointer);
            List<CertificateToken> certificates = otherListPointer.getSdiCertificates();
            assertNotNull(certificates);
            for (CertificateToken certificateToken : certificates) {
                assertNotNull(certificateToken);
            }
            assertNotNull(otherListPointer.getLocationUrl());
            assertNotNull(otherListPointer.getSchemeTerritory());
            assertNotNull(otherListPointer.getType());
            assertFalse(Utils.isMapEmpty(otherListPointer.getSchemeOperatorNames()));
            assertFalse(Utils.isMapEmpty(otherListPointer.getSchemeTypeCommunityRules()));
        }
    }
    
}
