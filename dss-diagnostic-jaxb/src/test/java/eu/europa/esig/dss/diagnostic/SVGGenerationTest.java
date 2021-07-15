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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Result;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SVGGenerationTest {

	@Test
	public void test() throws JAXBException, XMLStreamException, IOException, SAXException, TransformerException {
		DiagnosticDataFacade newFacade = DiagnosticDataFacade.newFacade();
		XmlDiagnosticData diagnosticData = newFacade.unmarshall(new File("src/test/resources/diag-data.xml"));

		try (FileOutputStream fos = new FileOutputStream("target/diag-data.svg")) {
			Result result = new StreamResult(fos);
			newFacade.generateSVG(diagnosticData, result);
		}
		
		File file = new File("target/diag-data.svg");
		assertTrue(file.exists());
		assertTrue(file.length() > 0);
		assertTrue(file.delete(), "Cannot delete the SVG file");
		assertFalse(file.exists());
	}

}
