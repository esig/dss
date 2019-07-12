package eu.europa.esig.jaxb.policy;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;

public final class ValidationPolicyXmlDefiner {

	public static final String VALIDATION_POLICY_SCHEMA_LOCATION = "/xsd/policy.xsd";

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	private ValidationPolicyXmlDefiner() {
	}

	// Thread-safe
	private static JAXBContext jc;
	// Thread-safe
	private static Schema schema;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream inputStream = ValidationPolicyXmlDefiner.class.getResourceAsStream(VALIDATION_POLICY_SCHEMA_LOCATION)) {
				SchemaFactory sf = XmlDefinerUtils.getSecureSchemaFactory();
				schema = sf.newSchema(new Source[] { new StreamSource(inputStream) });
			}
		}
		return schema;
	}


}
