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
package eu.europa.esig.dss.xml.common;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.SchemaFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XmlDefinerUtilsTest {

	@Test
	public void getSecureSchemaFactory() throws SAXException {
		assertNotNull(XmlDefinerUtils.getInstance().getSecureSchemaFactory());
	}

	@Test
	public void getSecureTransformerFactory() throws TransformerConfigurationException {
		assertNotNull(XmlDefinerUtils.getInstance().getSecureTransformerFactory());
	}

	@Test
	public void getSecureDocumentBuilderFactory() {
		assertNotNull(XmlDefinerUtils.getInstance().getSecureDocumentBuilderFactory());
	}

	@Test
	public void mockSecureSchemaFactoryBuilderTest() throws SAXException {
		MockSchemaFactoryBuilder schemaFactoryBuilder = new MockSchemaFactoryBuilder();

		SchemaFactory secureSchemaFactory = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
		assertNotNull(secureSchemaFactory);
		assertNotEquals(schemaFactoryBuilder.schemaFactory, secureSchemaFactory);

		XmlDefinerUtils.getInstance().setSchemaFactoryBuilder(schemaFactoryBuilder);
		secureSchemaFactory = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
		assertNotNull(secureSchemaFactory);
		assertEquals(schemaFactoryBuilder.schemaFactory, secureSchemaFactory);
	}

	private class MockSchemaFactoryBuilder extends SchemaFactoryBuilder {

		private SchemaFactory schemaFactory;

		@Override
		protected SchemaFactory instantiateFactory() {
			if (schemaFactory == null) {
				schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			}
			return schemaFactory;
		}

	}

	@Test
	public void mockTransformerFactoryBuilderTest() {
		MockTransformerFactoryBuilder transformerFactoryBuilder = new MockTransformerFactoryBuilder();

		TransformerFactory transformerFactory = XmlDefinerUtils.getInstance().getSecureTransformerFactory();
		assertNotNull(transformerFactory);
		assertNotEquals(transformerFactoryBuilder.transformerFactory, transformerFactory);

		XmlDefinerUtils.getInstance().setTransformerFactoryBuilder(transformerFactoryBuilder);
		transformerFactory = XmlDefinerUtils.getInstance().getSecureTransformerFactory();
		assertNotNull(transformerFactory);
		assertEquals(transformerFactoryBuilder.transformerFactory, transformerFactory);
	}

	private class MockTransformerFactoryBuilder extends TransformerFactoryBuilder {

		private TransformerFactory transformerFactory;

		@Override
		protected TransformerFactory instantiateFactory() {
			if (transformerFactory == null) {
				transformerFactory = TransformerFactory.newInstance();
			}
			return transformerFactory;
		}

	}

	@Test
	public void mockDocumentBuilderFactoryBuilderTest() {
		MockDocumentBuilderFactoryBuilder documentBuilderFactoryBuilder = new MockDocumentBuilderFactoryBuilder();

		DocumentBuilderFactory documentBuilderFactory = XmlDefinerUtils.getInstance().getSecureDocumentBuilderFactory();
		assertNotNull(documentBuilderFactory);
		assertNotEquals(documentBuilderFactoryBuilder.documentBuilderFactory, documentBuilderFactory);

		XmlDefinerUtils.getInstance().setDocumentBuilderFactoryBuilder(documentBuilderFactoryBuilder);
		documentBuilderFactory = XmlDefinerUtils.getInstance().getSecureDocumentBuilderFactory();
		assertNotNull(documentBuilderFactory);
		assertEquals(documentBuilderFactoryBuilder.documentBuilderFactory, documentBuilderFactory);
	}

	private class MockDocumentBuilderFactoryBuilder extends DocumentBuilderFactoryBuilder {

		private DocumentBuilderFactory documentBuilderFactory;

		@Override
		protected DocumentBuilderFactory instantiateFactory() {
			if (documentBuilderFactory == null) {
				documentBuilderFactory = DocumentBuilderFactory.newInstance();
			}
			return documentBuilderFactory;
		}

	}

}
