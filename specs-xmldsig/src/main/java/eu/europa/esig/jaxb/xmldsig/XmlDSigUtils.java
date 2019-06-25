package eu.europa.esig.jaxb.xmldsig;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

public final class XmlDSigUtils {

	public static final String XMLDSIG_SCHEMA_LOCATION = "/xsd/xmldsig-core-schema.xsd";

	private XmlDSigUtils() {
	}

	private static JAXBContext jc;
	private static Schema schema;

	public static JAXBContext getJAXBContext() {
		if (jc == null) {
			try {
				jc = JAXBContext.newInstance(ObjectFactory.class);
			} catch (JAXBException e) {
				throw new RuntimeException("Unable to initialize the JAXBContext", e);
			}
		}
		return jc;
	}

	public static Schema getSchema() {
		if (schema == null) {
			try (InputStream is = XmlDSigUtils.class.getResourceAsStream(XMLDSIG_SCHEMA_LOCATION)) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				schema = sf.newSchema(new StreamSource(is));
			} catch (IOException | SAXException e) {
				throw new RuntimeException("Unable to initialize the Schema", e);
			}
		}
		return schema;
	}

}
