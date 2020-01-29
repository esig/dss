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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class TrustedListFacadeTest {

	@Test
	public void testTL() throws JAXBException, XMLStreamException, IOException, SAXException {
		marshallUnmarshall(new File("src/test/resources/tl.xml"));
	}

	@Test
	public void testLOTL() throws JAXBException, XMLStreamException, IOException, SAXException {
		marshallUnmarshall(new File("src/test/resources/lotl.xml"));
	}

	private void marshallUnmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		TrustedListFacade facade = TrustedListFacade.newFacade();

		TrustStatusListType trustStatusListType = facade.unmarshall(file);
		assertNotNull(trustStatusListType);

		String marshall = facade.marshall(trustStatusListType, true);
		assertNotNull(marshall);
	}

}
