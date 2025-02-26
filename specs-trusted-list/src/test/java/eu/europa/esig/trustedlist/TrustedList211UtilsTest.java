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
package eu.europa.esig.trustedlist;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.UnmarshalException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrustedList211UtilsTest {

    private static TrustedList211Utils trustedList211Utils;

    @BeforeAll
    static void init() {
        trustedList211Utils = TrustedList211Utils.getInstance();
    }

    @Test
    void getJAXBContext() throws JAXBException {
        assertNotNull(trustedList211Utils.getJAXBContext());
        // cached
        assertNotNull(trustedList211Utils.getJAXBContext());
    }

    @Test
    void getSchema() throws SAXException {
        assertNotNull(trustedList211Utils.getSchema());
        // cached
        assertNotNull(trustedList211Utils.getSchema());
    }

    @Test
    void lotlTest() throws JAXBException, SAXException {
        File xmldsigFile = new File("src/test/resources/lotl.xml");
        marshallUnmarshall(xmldsigFile);
    }

    @Test
    void tlTest() throws JAXBException, SAXException {
        File xmldsigFile = new File("src/test/resources/tl.xml");
        marshallUnmarshall(xmldsigFile);
    }

    @Test
    void tlv5Test() throws JAXBException, SAXException {
        File xmldsigFile = new File("src/test/resources/tlv5.xml");
        marshallUnmarshall(xmldsigFile);
    }

    @Test
    void tlv6Test() {
        File xmldsigFile = new File("src/test/resources/tlv6.xml");
        UnmarshalException exception = assertThrows(UnmarshalException.class, () -> marshallUnmarshall(xmldsigFile));
        assertTrue(exception.getCause().getMessage().contains("ServiceSupplyPoint"));
    }

    private void marshallUnmarshall(File xmlFile) throws JAXBException, SAXException {
        JAXBContext jc = trustedList211Utils.getJAXBContext();
        assertNotNull(jc);

        Schema schema = trustedList211Utils.getSchema();
        assertNotNull(schema);

        Unmarshaller unmarshaller = jc.createUnmarshaller();
        unmarshaller.setSchema(schema);

        JAXBElement<?> unmarshalled = (JAXBElement<?>) unmarshaller.unmarshal(xmlFile);
        assertNotNull(unmarshalled);
    }

}
