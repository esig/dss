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
package eu.europa.esig.xmlers;

import eu.europa.esig.xmlers.jaxb.EvidenceRecordType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class XMLEvidenceRecordTest {

    private static XMLEvidenceRecordUtils xmlersUtils;

    @BeforeAll
    static void init() {
        xmlersUtils = XMLEvidenceRecordUtils.getInstance();
    }

    private static Stream<Arguments> data() {
        File folder = new File("src/test/resources");
        Collection<Arguments> dataToRun = new ArrayList<>();
        for (File file : getDirectoryFiles(folder)) {
            dataToRun.add(Arguments.of(file));
        }
        return dataToRun.stream();
    }

    private static List<File> getDirectoryFiles(File file) {
        List<File> result = new ArrayList<>();
        if (file.isFile()) {
            result.add(file);
        } else if (file.isDirectory()) {
            for (File subFile : file.listFiles()) {
                result.addAll(getDirectoryFiles(subFile));
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    @ParameterizedTest(name = "Validation {index} : {0}")
    @MethodSource("data")
    void testMarshalling(File xmlersFile) throws JAXBException, SAXException {
        JAXBContext jc = xmlersUtils.getJAXBContext();
        assertNotNull(jc);

        Schema schema = xmlersUtils.getSchema();
        assertNotNull(schema);

        Unmarshaller unmarshaller = jc.createUnmarshaller();
        unmarshaller.setSchema(schema);

        JAXBElement<EvidenceRecordType> unmarshalled = (JAXBElement<EvidenceRecordType>) unmarshaller.unmarshal(xmlersFile);
        assertNotNull(unmarshalled);
        assertNotNull(unmarshalled.getValue());

        Marshaller marshaller = jc.createMarshaller();
        marshaller.setSchema(schema);

        StringWriter sw = new StringWriter();
        marshaller.marshal(unmarshalled, sw);

        String xmlerString = sw.toString();

        JAXBElement<EvidenceRecordType> unmarshalled2 = (JAXBElement<EvidenceRecordType>) unmarshaller.unmarshal(new StringReader(xmlerString));
        assertNotNull(unmarshalled2);
        assertNotNull(unmarshalled2.getValue());
    }

    @Test
    void getJAXBContext() throws JAXBException {
        assertNotNull(xmlersUtils.getJAXBContext());
        // cached
        assertNotNull(xmlersUtils.getJAXBContext());
    }

}
