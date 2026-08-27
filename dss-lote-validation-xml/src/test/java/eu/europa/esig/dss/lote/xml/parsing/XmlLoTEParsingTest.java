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

import eu.europa.esig.dss.lote.parsing.AbstractLoTEParsingResult;
import eu.europa.esig.dss.lote.parsing.LoTEParsingResult;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.lote.ServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.lote.TrustedEntity;
import eu.europa.esig.dss.model.lote.TrustedEntityService;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlLoTEParsingTest {

    @Test
    void testValid() {
        DSSDocument lote = new FileDocument("src/test/resources/lote-pubeaa.xml");
        XmlLoTEParsingTask task = new XmlLoTEParsingTask(lote, new LoTESource());
        AbstractLoTEParsingResult result = task.get();
        assertNotNull(result);
        assertEquals(1, result.getVersion());
        assertEquals(1, result.getSequenceNumber());
        assertNotNull(result.getIssueDate());
        assertNotNull(result.getNextUpdateDate());
        assertEquals("EU", result.getTerritory());
        assertFalse(Utils.isCollectionNotEmpty(result.getDistributionPoints()));
        assertFalse(Utils.isCollectionNotEmpty(result.getStructureValidationMessages()));

        List<TrustedEntity> trustedEntities = result.getTrustedEntities();
        assertNotNull(trustedEntities);
        assertEquals(1, trustedEntities.size());

        checkTEs(trustedEntities);

        for (int i = 0; i < trustedEntities.size(); i++) {
            TrustedEntity trustedEntity = trustedEntities.get(i);
            assertEquals(1, trustedEntity.getServices().size());
        }
    }

    @Test
    void testBrokenStructure() {
        DSSDocument lote = new FileDocument("src/test/resources/lote-pubeaa-not-parsable.xml");
        XmlLoTEParsingTask task = new XmlLoTEParsingTask(lote, new LoTESource());
        Exception exception = assertThrows(DSSException.class, task::get);
        assertTrue(exception.getMessage().contains("Unable to parse binaries."));
    }

    @Test
    void testJson() {
        DSSDocument lote = new FileDocument("src/test/resources/lote-pubeaa.json");
        XmlLoTEParsingTask task = new XmlLoTEParsingTask(lote, new LoTESource());
        Exception exception = assertThrows(DSSException.class, task::get);
        assertTrue(exception.getMessage().contains("Unable to parse binaries."));
    }

    @Test
    void testStructureError() {
        DSSDocument lote = new FileDocument("src/test/resources/lote-pubeaa-not-compliant.xml");
        XmlLoTEParsingTask task = new XmlLoTEParsingTask(lote, new LoTESource());
        AbstractLoTEParsingResult result = task.get();
        assertNotNull(result);
        assertNull(result.getVersion());
        assertEquals(1, result.getSequenceNumber());
        assertNotNull(result.getIssueDate());
        assertNotNull(result.getNextUpdateDate());
        assertEquals("EU", result.getTerritory());
        assertFalse(Utils.isCollectionNotEmpty(result.getDistributionPoints()));
        assertTrue(Utils.isCollectionNotEmpty(result.getStructureValidationMessages()));
        assertTrue(result.getStructureValidationMessages().stream().anyMatch(m -> m.contains("LoTEVersionIdentifier")));

        List<TrustedEntity> trustedEntities = result.getTrustedEntities();
        assertNotNull(trustedEntities);
        assertEquals(1, trustedEntities.size());
    }

    @Test
    void testLoTEEmpty() {
        DSSDocument lote = new FileDocument("src/test/resources/lote-pubeaa-empty.xml");
        LoTESource loteSource = new LoTESource();
        XmlLoTEParsingTask task = new XmlLoTEParsingTask(lote, loteSource);
        LoTEParsingResult result = task.get();
        assertNotNull(result);
        assertNull(result.getVersion());
        assertNull(result.getSequenceNumber());
        assertNull(result.getIssueDate());
        assertNull(result.getNextUpdateDate());
        assertNull(result.getTerritory());
        assertTrue(Utils.isCollectionEmpty(result.getDistributionPoints()));
        assertFalse(Utils.isCollectionEmpty(result.getStructureValidationMessages()));

        List<TrustedEntity> trustedEntities = result.getTrustedEntities();
        assertNotNull(trustedEntities);
        assertEquals(0, trustedEntities.size());
    }

    @Test
    void testBrokenSignature() {
        DSSDocument lote = new FileDocument("src/test/resources/lote-pubeaa-broken-sig.xml");
        XmlLoTEParsingTask task = new XmlLoTEParsingTask(lote, new LoTESource());
        AbstractLoTEParsingResult result = task.get();
        assertNotNull(result);
        assertEquals(1, result.getVersion());
        assertEquals(1, result.getSequenceNumber());
        assertNotNull(result.getIssueDate());
        assertNotNull(result.getNextUpdateDate());
        assertEquals("EU", result.getTerritory());
        assertFalse(Utils.isCollectionNotEmpty(result.getDistributionPoints()));
        assertFalse(Utils.isCollectionNotEmpty(result.getStructureValidationMessages()));
    }

    private void checkTEs(List<TrustedEntity> trustedEntities) {
        for (TrustedEntity te : trustedEntities) {

            assertNotNull(te.getNames());
            assertFalse(te.getNames().isEmpty());

            assertNotNull(te.getTradeNames());
            assertFalse(te.getTradeNames().isEmpty());

            assertNotNull(te.getElectronicAddresses());
            assertFalse(te.getElectronicAddresses().isEmpty());

            assertNotNull(te.getPostalAddresses());
            assertFalse(te.getPostalAddresses().isEmpty());

            assertNotNull(te.getInformation());
            assertFalse(te.getInformation().isEmpty());

            assertNotNull(te.getServices());
            assertFalse(te.getServices().isEmpty());

            checkServices(te.getServices());
        }
    }

    private void checkServices(List<TrustedEntityService> services) {
        for (TrustedEntityService entityService : services) {
            assertNotNull(entityService.getCertificates());
            assertFalse(entityService.getCertificates().isEmpty());

            TimeDependentValues<ServiceStatusAndInformationExtensions> statusAndInformationExtensions = entityService.getStatusAndInformationExtensions();
            assertNotNull(statusAndInformationExtensions);

            ServiceStatusAndInformationExtensions latest = statusAndInformationExtensions.getLatest();
            assertNotNull(latest);

            assertNotNull(latest.getNames());
            assertFalse(latest.getNames().isEmpty());

            assertNotNull(latest.getType());
        }
    }
    
}
