package eu.europa.esig.dss.jaxb.parsers;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

public class MarshallerBuilder {

	private final JAXBContext jaxbContext;
	private final Schema schema;

	private boolean validate = true;
	private boolean indent = false;

	public MarshallerBuilder(JAXBContext jaxbContext, Schema schema) {
		this.jaxbContext = jaxbContext;
		this.schema = schema;
	}

	public MarshallerBuilder setValidate(boolean validate) {
		this.validate = validate;
		return this;
	}

	public MarshallerBuilder setIndent(boolean indent) {
		this.indent = indent;
		return this;
	}

	public Marshaller buildMarshaller() throws JAXBException {
		Marshaller marshaller = jaxbContext.createMarshaller();

		if (validate) {
			marshaller.setSchema(schema);
		}

		if (indent) {
			marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		}

		return marshaller;
	}

	public Unmarshaller buildUnmarshaller() throws JAXBException {
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();

		if (validate) {
			unmarshaller.setSchema(schema);
		}

		return unmarshaller;
	}

}
