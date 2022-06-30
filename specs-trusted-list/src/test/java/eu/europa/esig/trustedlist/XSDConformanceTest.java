package eu.europa.esig.trustedlist;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;


import java.io.File;
import java.io.FileInputStream;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;


public class XSDConformanceTest {

	@Test
	public void test() {
		
		try {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
			List<Source> xsdSources = new ArrayList<Source>();
            xsdSources.add(new StreamSource(new FileInputStream( new File("src/test/resources/xsd/xml.xsd"))));
            xsdSources.add(new StreamSource(new FileInputStream( new File("src/test/resources/xsd/xmldsig-core-schema.xsd"))));
            xsdSources.add(new StreamSource(new FileInputStream( new File("src/test/resources/xsd/xades.xsd"))));
            xsdSources.add(new StreamSource(new FileInputStream( new File("src/test/resources/xsd/ts_xsd.xsd"))));
            xsdSources.add(new StreamSource(new FileInputStream( new File("src/test/resources/xsd/ts_additionaltypes_xsd.xsd"))));
            xsdSources.add(new StreamSource(new FileInputStream( new File("src/main/resources/xsd/MRA-info_qc_esig-v0.03.xsd"))));
            

			Schema schema = sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
			System.out.println("Schema loaded");
			
			Validator validator = schema.newValidator();
		
			validator.validate(new StreamSource(new FileInputStream( new File("src/test/resources/mra/lotl_with_tc-v0.03.xml"))));
			System.out.println("XML validated");
		} catch (SAXException | IOException e) {
			e.printStackTrace();
		}

	}

}
