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
package eu.europa.esig.dss.lote.xml.download;

import eu.europa.esig.dss.lote.download.LoTEDownloadResult;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XmlLoTEDownloadTaskTest {

    @Test
    void testValid() {
        DSSDocument trustedList = new FileDocument("src/test/resources/lote-pubeaa.xml");
        XmlLoTEDownloadTask task = new XmlLoTEDownloadTask(trustedList, "https://dss.nowina.lu/lote-pubeaa.xml");
        LoTEDownloadResult result = task.get();
        assertNotNull(result);
        assertNotNull(result.getDSSDocument());
        assertNotNull(result.getDigest());
        assertFalse(result.getDigest().isEmpty());
    }

    @Test
    void nullResultTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new XmlLoTEDownloadTask(null, null));
        assertEquals("The url is null", exception.getMessage());

        Map<String, DSSDocument> dataMap = new HashMap<>();
        dataMap.put("null", null);
        dataMap.put("empty-document", new InMemoryDocument());
        dataMap.put("empty-array", new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY));
        dataMap.put("0", new InMemoryDocument(new byte[] { 0 }));
        dataMap.put("digestDoc", new DigestDocument());
        for (Map.Entry<String, DSSDocument> entry : dataMap.entrySet()) {
            XmlLoTEDownloadTask task = new XmlLoTEDownloadTask(entry.getValue(), entry.getKey());
            assertThrows(DSSException.class, task::get);
        }
    }

    @Test
    void notXmlTest() {
        Map<String, DSSDocument> dataMap = new HashMap<>();
        dataMap.put("text", new InMemoryDocument("text".getBytes()));
        dataMap.put("broken-xml", new InMemoryDocument("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListOfTrustedEntities>".getBytes()));
        dataMap.put("json", new InMemoryDocument("{ \"hello\" : \"world\" }".getBytes()));
        dataMap.put("sd-jwt", new InMemoryDocument("ey.ey.ey~".getBytes()));
        for (Map.Entry<String, DSSDocument> entry : dataMap.entrySet()) {
            XmlLoTEDownloadTask task = new XmlLoTEDownloadTask(entry.getValue(), entry.getKey());
            assertThrows(DSSException.class, task::get);
        }
    }

}
