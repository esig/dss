package eu.europa.esig.xmldsig;

import java.util.Arrays;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;

public abstract class XSDAbstractUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XSDAbstractUtils.class);
	
	private static final String EMPTY_STRING = "";

	/**
	 * Returns a JAXBContext
	 * @return {@link JAXBContext}
	 * @throws JAXBException in case of an exception
	 */
	public abstract JAXBContext getJAXBContext() throws JAXBException;
	
	/**
	 * Returns a default module {@code Schema}
	 * @return {@link Schema}
	 * @throws SAXException in case of an exception
	 */
	public abstract Schema getSchema() throws SAXException;
	
	/**
	 * Returns a Schema with custom sources
	 * @param sources an array of custom {@link Source}s
	 * @return {@link Schema}
	 * @throws SAXException in case of an exception
	 */
	public Schema getSchema(Source... sources) throws SAXException {
		List<Source> xsdSources = getXSDSources();
		if (sources != null) {
			xsdSources.addAll(Arrays.asList(sources));
		}
		return XmlDefinerUtils.getSchema(xsdSources);
	}

	/**
	 * This method allows to validate an XML against the module-default XSD schema.
	 *
	 * @param streamSource
	 *            {@code InputStream} XML to validate
	 * @return null if the XSD validates the XML, error message otherwise
	 */
	public String validateAgainstXSD(final StreamSource streamSource) {
		try {
			return validate(getSchema(), streamSource);
		} catch (Exception e) {
			LOG.warn("Error during the XML schema validation!", e);
			return e.getMessage();
		}
	}

	/**
	 * This method allows to validate an XML against the module-default XSD schema plus custom sources.
	 *
	 * @param streamSource
	 *            {@code InputStream} XML to validate
	 * @param sources
	 *            {@code Source}s to validate against
	 * @return null if the XSD validates the XML, error message otherwise
	 */
	public String validateAgainstXSD(final StreamSource streamSource, Source... sources) {
		try {
			return validate(getSchema(sources), streamSource);
		} catch (Exception e) {
			LOG.warn("Error during the XML schema validation!", e);
			return e.getMessage();
		}
	}
	
	private String validate(final Schema schema, final StreamSource streamSource) throws Exception {
		Validator validator = schema.newValidator();
		avoidXXE(validator);
		validator.validate(streamSource);
		return EMPTY_STRING;
	}

	/**
	 * The method protects the validator against XXE
	 * (https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#validator)
	 * 
	 * @param validator
	 *                  the validator to be configured against XXE
	 * @throws SAXException
	 */
	private static void avoidXXE(Validator validator) throws SAXException {
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
	}
	
	/**
	 * Returns a list of module-specific XSD {@code Source}s
	 * @return list of XSD {@link Source}s
	 */
	public abstract List<Source> getXSDSources();

}
