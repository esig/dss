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
package eu.europa.esig.dss.pki.jaxb;

import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PKIJaxbFacadeTest extends AbstractTestJaxbPKI {

    static Stream<Arguments> data() {
        List<Arguments> dataToRun = new ArrayList<>();
        Collection<File> pkiFiles = Utils.listFiles(new File(XML_FOLDER), new String[]{"xml"}, false);
        for (File file : pkiFiles) {
            dataToRun.add(Arguments.of(file));
        }
        return dataToRun.stream();
    }

    @ParameterizedTest(name = "PKI {index} : {0}")
    @MethodSource("data")
    void testUnmarshall(File pkiFile) throws XMLStreamException, JAXBException, IOException, SAXException {
        XmlPki xmlPki = PKIJaxbFacade.newFacade().unmarshall(pkiFile);
        assertNotNull(xmlPki);
        assertTrue(xmlPki.getCertificate().size() > 0);
    }

}
