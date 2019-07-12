package eu.europa.esig.dss.jaxb.parsers;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

/**
 * Generic JAXB Facade which contains basic marshalling/unmarshalling
 * operations.
 * 
 * @param T
 *          A JAXB Object
 */
public abstract class AbstractJaxbFacade<T> {

	/**
	 * This method returns the instance of {@link JAXBContext} which can handle the
	 * JAXB Object
	 * 
	 * @return an instance of {@link JAXBContext}
	 * @throws JAXBException
	 *                       if an error occurred in the initialization process
	 */
	protected abstract JAXBContext getJAXBContext() throws JAXBException;

	/**
	 * This method returns an instance of {@link Schema} with the loaded XML
	 * Schema(s). The XSD(s) allows to validate the JAXB Object.
	 * 
	 * @return an instance of {@link Schema}
	 * @throws IOException
	 *                      if an I/O error occurred in the initialization process
	 * @throws SAXException
	 *                      if a SAX error occurred in the initialization process
	 */
	protected abstract Schema getSchema() throws IOException, SAXException;

	/**
	 * This method wraps/envelops the JAXB object with a "root" element
	 * 
	 * @param jaxbObject
	 *                   the JAXB object to be enveloped to marshall
	 * @return the enveloped JAXB object, ready to be marshalled
	 */
	protected abstract JAXBElement<T> wrap(T jaxbObject);

	/**
	 * This method returns the String representation of the jaxbObject.
	 * 
	 * The validation of the jaxbObject against its related XSD is enabled.
	 * 
	 * @param jaxbObject
	 *                   the jaxb object to be marshalled
	 * @return the result of the marshalling for the given jaxbObject
	 * @throws JAXBException
	 *                       if an exception occurred with the {@link JAXBContext}
	 * @throws IOException
	 *                       if an exception occurred with the I/O.
	 * @throws SAXException
	 *                       if an exception occurred with the {@link Schema}
	 */
	public String marshall(T jaxbObject) throws JAXBException, IOException, SAXException {
		return marshall(jaxbObject, true);
	}

	/**
	 * This method returns the String representation of the jaxbObject with an
	 * optional validation.
	 * 
	 * @param jaxbObject
	 *                   the jaxb object to be marshalled
	 * @param validate
	 *                   enable/disable the validation against the related XSD
	 * @return the result of the marshalling for the given jaxbObject
	 * @throws JAXBException
	 *                       if an exception occurred with the {@link JAXBContext}
	 * @throws IOException
	 *                       if an exception occurred with the I/O.
	 * @throws SAXException
	 *                       if an exception occurred with the {@link Schema}
	 */
	public String marshall(T jaxbObject, boolean validate) throws JAXBException, IOException, SAXException {
		Marshaller marshaller = getMarshaller(validate);

		try (StringWriter writer = new StringWriter()) {
			marshaller.marshal(wrap(jaxbObject), writer);
			return writer.toString();
		}
	}

	/**
	 * This method marshalls the jaxbObject into the {@link OutputStream}.
	 * 
	 * The validation of the jaxbObject against its related XSD is enabled.
	 * 
	 * @param jaxbObject
	 *                   the jaxb object to be marshalled
	 * @param os
	 *                   the {@link OutputStream} where the object will be
	 *                   marshalled.
	 * @throws JAXBException
	 *                       if an exception occurred with the {@link JAXBContext}
	 * @throws IOException
	 *                       if an exception occurred with the I/O.
	 * @throws SAXException
	 *                       if an exception occurred with the {@link Schema}
	 */
	public void marshall(T jaxbObject, OutputStream os) throws JAXBException, SAXException, IOException {
		marshall(jaxbObject, os, true);
	}

	/**
	 * This method marshalls the jaxbObject into the {@link OutputStream} with an
	 * optional validation.
	 * 
	 * @param jaxbObject
	 *                   the jaxb object to be marshalled
	 * @param os
	 *                   the {@link OutputStream} where the object will be
	 *                   marshalled
	 * @param validate
	 *                   enable/disable the validation against the related XSD
	 * @throws JAXBException
	 *                       if an exception occurred with the {@link JAXBContext}
	 * @throws IOException
	 *                       if an exception occurred with the I/O.
	 * @throws SAXException
	 *                       if an exception occurred with the {@link Schema}
	 */
	public void marshall(T jaxbObject, OutputStream os, boolean validate) throws JAXBException, SAXException, IOException {
		Marshaller marshaller = getMarshaller(validate);

		marshaller.marshal(wrap(jaxbObject), os);
	}

	/**
	 * This method unmarshalls the {@link InputStream} and returns an instance of
	 * the JAXB Object.
	 * 
	 * The validation of the {@link InputStream} against its related XSD is enabled.
	 * 
	 * @param is
	 *           the {@link InputStream} which contains a XML representation of JAXB
	 *           Object.
	 * @return an instance of the JAXB Object
	 * @throws JAXBException
	 *                            if an exception occurred with the
	 *                            {@link JAXBContext}
	 * @throws XMLStreamException
	 *                            if an exception occurred with the source
	 * @throws IOException
	 *                            if an exception occurred with the I/O.
	 * @throws SAXException
	 *                            if an exception occurred with the {@link Schema}
	 */
	public T unmarshall(InputStream is) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(is, true);
	}

	/**
	 * This method unmarshalls the {@link InputStream} and returns an instance of
	 * the JAXB Object with an optional validation.
	 * 
	 * @param is
	 *                 the {@link InputStream} which contains a XML representation
	 *                 of JAXB Object.
	 * @param validate
	 *                 enable/disable the validation against the related XSD
	 * @return an instance of JAXB Object
	 * @throws JAXBException
	 *                            if an exception occurred with the
	 *                            {@link JAXBContext}
	 * @throws XMLStreamException
	 *                            if an exception occurred with the source
	 * @throws IOException
	 *                            if an exception occurred with the I/O.
	 * @throws SAXException
	 *                            if an exception occurred with the {@link Schema}
	 */
	public T unmarshall(InputStream is, boolean validate) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(new StreamSource(is), validate);
	}

	/**
	 * This method unmarshalls the {@link File} and returns an instance of the JAXB
	 * Object.
	 * 
	 * The validation of the {@link File} against its related XSD is enabled.
	 * 
	 * @param file
	 *             the {@link File} which contains a XML representation of JAXB
	 *             Object.
	 * @return an instance of JAXB Object
	 * @throws JAXBException
	 *                            if an exception occurred with the
	 *                            {@link JAXBContext}
	 * @throws XMLStreamException
	 *                            if an exception occurred with the source
	 * @throws IOException
	 *                            if an exception occurred with the I/O.
	 * @throws SAXException
	 *                            if an exception occurred with the {@link Schema}
	 */
	public T unmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(file, true);
	}

	/**
	 * This method unmarshalls the {@link File} and returns an instance of the JAXB
	 * Object with an optional validation.
	 * 
	 * @param file
	 *                 the {@link File} which contains a XML representation of JAXB
	 *                 Object.
	 * @param validate
	 *                 enable/disable the validation against the related XSD
	 * @return an instance of JAXB Object
	 * @throws JAXBException
	 *                            if an exception occurred with the
	 *                            {@link JAXBContext}
	 * @throws XMLStreamException
	 *                            if an exception occurred with the source
	 * @throws IOException
	 *                            if an exception occurred with the I/O.
	 * @throws SAXException
	 *                            if an exception occurred with the {@link Schema}
	 */
	public T unmarshall(File file, boolean validate) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(new StreamSource(file), validate);
	}

	/**
	 * This method unmarshalls the {@link String} and returns an instance of the
	 * JAXB Object.
	 * 
	 * The validation of the {@link String} against its related XSD is enabled.
	 * 
	 * @param xmlObject
	 *                  the {@link String} which contains a XML representation of
	 *                  JAXB Object.
	 * @return an instance of JAXB Object
	 * @throws JAXBException
	 *                            if an exception occurred with the
	 *                            {@link JAXBContext}
	 * @throws XMLStreamException
	 *                            if an exception occurred with the source
	 * @throws IOException
	 *                            if an exception occurred with the I/O.
	 * @throws SAXException
	 *                            if an exception occurred with the {@link Schema}
	 */
	public T unmarshall(String xmlObject) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(xmlObject, true);
	}

	/**
	 * This method unmarshalls the {@link String} and returns an instance of the
	 * JAXB Object with an optional validation.
	 * 
	 * @param xmlObject
	 *                  the {@link String} which contains a XML representation of
	 *                  JAXB Object.
	 * @param validate
	 *                  enable/disable the validation against the related XSD
	 * @return an instance of JAXB Object
	 * @throws JAXBException
	 *                            if an exception occurred with the
	 *                            {@link JAXBContext}
	 * @throws XMLStreamException
	 *                            if an exception occurred with the source
	 * @throws IOException
	 *                            if an exception occurred with the I/O.
	 * @throws SAXException
	 *                            if an exception occurred with the {@link Schema}
	 */
	public T unmarshall(String xmlObject, boolean validate) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(new StreamSource(new StringReader(xmlObject)), validate);
	}

	@SuppressWarnings("unchecked")
	private T unmarshall(Source source, boolean validate) throws JAXBException, XMLStreamException, IOException, SAXException {
		Unmarshaller unmarshaller = getUnmarshaller(validate);

		JAXBElement<T> unmarshal = (JAXBElement<T>) unmarshaller.unmarshal(avoidXXE(source));
		return unmarshal.getValue();
	}

	public Marshaller getMarshaller(boolean validate) throws JAXBException, SAXException, IOException {
		Marshaller marshaller = getJAXBContext().createMarshaller();
		if (validate) {
			marshaller.setSchema(getSchema());
		}
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		return marshaller;
	}

	public Unmarshaller getUnmarshaller(boolean validate) throws JAXBException, IOException, SAXException {
		Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
		if (validate) {
			unmarshaller.setSchema(getSchema());
		}
		return unmarshaller;
	}

	private XMLStreamReader avoidXXE(Source source) throws XMLStreamException {
		XMLInputFactory xif = XMLInputFactory.newFactory();
		xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		return xif.createXMLStreamReader(source);
	}

}
