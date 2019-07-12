package eu.europa.esig.jaxb.policy;

import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;

public class ValidationPolicyFacade extends AbstractJaxbFacade<ConstraintsParameters> {

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

}
