package eu.europa.esig.dss.jaxb.diagnostic;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

public final class DiagnosticDataXmlDefiner {

	public static final String DIAGNOSTIC_DATA_SCHEMA_LOCATION = "/xsd/DiagnosticData.xsd";

	private DiagnosticDataXmlDefiner() {
	}

	// Thread-safe
	private static JAXBContext jc;
	// Thread-safe
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
			try (InputStream isXSDDiagnosticData = DiagnosticDataXmlDefiner.class.getResourceAsStream(DIAGNOSTIC_DATA_SCHEMA_LOCATION)) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				schema = sf.newSchema(new Source[] { new StreamSource(isXSDDiagnosticData) });
			} catch (IOException | SAXException e) {
				throw new RuntimeException("Unable to initialize the Schema", e);
			}
		}
		return schema;
	}

}
