package eu.europa.esig.xmldsig;

import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.transform.Source;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public abstract class AbstractUtils {

	protected static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();
	
	protected static JAXBContext jc;
	protected static Schema schema;

	public static Schema getSchema(List<Source> xsdSources) throws SAXException {
		SchemaFactory sf = XmlDefinerUtils.getSecureSchemaFactory();
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		sf.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		return sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
	}
	
	public static Validator getValidator(List<Source> sources) throws SAXException {
		if (schema == null) {
			schema = getSchema(sources);
		}
		Validator validator = schema.newValidator();
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		return validator;
	}
	
}
