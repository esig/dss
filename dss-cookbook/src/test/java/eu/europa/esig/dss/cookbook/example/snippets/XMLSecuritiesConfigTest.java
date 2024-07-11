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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.xml.common.DocumentBuilderFactoryBuilder;
import eu.europa.esig.dss.xml.common.TransformerFactoryBuilder;
import eu.europa.esig.dss.xml.common.XmlDefinerUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class XMLSecuritiesConfigTest {
	
	@Test
	void test() throws Exception {

		// tag::demo[]
		// import eu.europa.esig.dss.alert.LogOnStatusAlert;
		// import eu.europa.esig.dss.xml.common.TransformerFactoryBuilder;
		// import eu.europa.esig.dss.xml.common.XmlDefinerUtils;
		// import org.slf4j.event.Level;
		// import javax.xml.XMLConstants;
		// import javax.xml.transform.TransformerFactory;
		
		// Obtain a singleton instance of {@link XmlDefinerUtils}
		XmlDefinerUtils xmlDefinerUtils = XmlDefinerUtils.getInstance();
		
		// returns a predefined {@link TransformerFactoryBuilder} with all securities in place
		TransformerFactoryBuilder transformerBuilder = TransformerFactoryBuilder.getSecureTransformerBuilder();
		
		// sets an alert in case of exception on feature/attribute setting
		transformerBuilder.setSecurityExceptionAlert(new LogOnStatusAlert(Level.WARN));
		
		// allows to enable a feature
		transformerBuilder.enableFeature(XMLConstants.FEATURE_SECURE_PROCESSING);
		
		// allows to disable a feature
		transformerBuilder.disableFeature("FEATURE_TO_DISABLE");
		
		// allows to set an attribute with a value
		transformerBuilder.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		
		// sets the transformer (will be applied for all calls)
		xmlDefinerUtils.setTransformerFactoryBuilder(transformerBuilder);

		// end::demo[]
		
		TransformerFactory transformerFactory = transformerBuilder.build();
		assertNotNull(transformerFactory);

		// tag::dbf[]
		// import eu.europa.esig.dss.jaxb.common.DocumentBuilderFactoryBuilder;
		// import javax.xml.XMLConstants;

		// returns a configured secure instance of {@link DocumentBuilderFactoryBuilder}
		DocumentBuilderFactoryBuilder documentBuilderFactoryBuilder = DocumentBuilderFactoryBuilder.getSecureDocumentBuilderFactoryBuilder();

		// allows enabling of a feature
		documentBuilderFactoryBuilder.enableFeature("http://xml.org/sax/features/external-general-entities");
		
		// allows disabling of a feature
		documentBuilderFactoryBuilder.disableFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd");

		// allows to set an attribute
		documentBuilderFactoryBuilder.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");

		// sets the DocumentBuilderFactoryBuilder (will be applied for all calls)
		xmlDefinerUtils.setDocumentBuilderFactoryBuilder(documentBuilderFactoryBuilder);
		
		// end::dbf[]
		
	}

}
