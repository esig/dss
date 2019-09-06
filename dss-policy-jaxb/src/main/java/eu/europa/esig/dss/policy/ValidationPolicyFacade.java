package eu.europa.esig.dss.policy;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;

public class ValidationPolicyFacade extends AbstractJaxbFacade<ConstraintsParameters> {

	public static final String DEFAULT_VALIDATION_POLICY_LOCATION = "/policy/constraint.xml";
	public static final String TRUSTED_LIST_VALIDATION_POLICY_LOCATION = "/policy/tsl-constraint.xml";

	public static ValidationPolicyFacade newFacade() {
		return new ValidationPolicyFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return ValidationPolicyXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return ValidationPolicyXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<ConstraintsParameters> wrap(ConstraintsParameters jaxbObject) {
		return ValidationPolicyXmlDefiner.OBJECT_FACTORY.createConstraintsParameters(jaxbObject);
	}

	public ValidationPolicy getDefaultValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		return getValidationPolicy((InputStream) null);
	}

	public ValidationPolicy getTrustedListValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream is = ValidationPolicyFacade.class.getResourceAsStream(TRUSTED_LIST_VALIDATION_POLICY_LOCATION)) {
			return getValidationPolicy(is);
		}
	}

	public ValidationPolicy getValidationPolicy(String path) throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream is = ValidationPolicyFacade.class.getResourceAsStream(path)) {
			return getValidationPolicy(is);
		}
	}

	public ValidationPolicy getValidationPolicy(InputStream is) throws JAXBException, XMLStreamException, IOException, SAXException {
		if (is == null) {
			return loadDefault();
		}
		return new EtsiValidationPolicy(unmarshall(is));
	}

	public ValidationPolicy getValidationPolicy(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		if (file == null) {
			return loadDefault();
		}
		return new EtsiValidationPolicy(unmarshall(file));
	}

	private ValidationPolicy loadDefault() throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream defaultIs = ValidationPolicyFacade.class.getResourceAsStream(DEFAULT_VALIDATION_POLICY_LOCATION)) {
			return getValidationPolicy(defaultIs);
		}
	}

}
