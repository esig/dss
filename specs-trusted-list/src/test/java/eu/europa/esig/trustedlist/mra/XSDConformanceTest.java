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
package eu.europa.esig.trustedlist.mra;

import eu.europa.esig.trustedlist.TrustedListUtils;
import eu.europa.esig.xades.XAdESUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.fail;


class XSDConformanceTest {

	private static final Logger LOG = LoggerFactory.getLogger(XSDConformanceTest.class);

	@Test
	void test() {
		
		try {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
			List<Source> xsdSources = new ArrayList<Source>();
            xsdSources.addAll(XmlDSigUtils.getInstance().getXSDSources());
            xsdSources.addAll(XAdESUtils.getInstance().getXSDSources());
            xsdSources.addAll(TrustedListUtils.getInstance().getXSDSources());
            xsdSources.addAll(MRAUtils.getInstance().getXSDSources());

			Schema schema = sf.newSchema(xsdSources.toArray(new Source[0]));
			LOG.info("Schema loaded");
			
			Validator validator = schema.newValidator();
		
			validator.validate(new StreamSource(Files.newInputStream(new File("src/test/resources/mra/mra-lotl.xml").toPath())));
			LOG.info("XML validated");

		} catch (SAXException | IOException e) {
			fail(e);
		}

	}

}
