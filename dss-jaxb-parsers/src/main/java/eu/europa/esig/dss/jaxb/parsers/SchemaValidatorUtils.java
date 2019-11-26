package eu.europa.esig.dss.jaxb.parsers;

import java.io.IOException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;

public class SchemaValidatorUtils {

	/**
	 * This method allows to validate a StreamSource XML against an XSD schema.
	 *
	 * @param schema
	 *            {@code Schema} to validate stream against
	 * @param streamSource
	 *            {@code StreamSource} representing an XML document to validate	
	 * @throws SAXException
	 *             if the document content is not valid
	 */
	public static void validateAgainstXSD(final Schema schema, final StreamSource streamSource) throws SAXException, IOException {
		final Validator validator = schema.newValidator();
		avoidXXE(validator);
		validator.validate(streamSource);
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

}
