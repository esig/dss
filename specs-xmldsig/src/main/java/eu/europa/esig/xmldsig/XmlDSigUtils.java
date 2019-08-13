package eu.europa.esig.xmldsig;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public final class XmlDSigUtils {

	public static final String XML_SCHEMA_LOCATION = "/xsd/xml.xsd";
	public static final String XMLDSIG_SCHEMA_LOCATION = "/xsd/xmldsig-core-schema.xsd";

	private XmlDSigUtils() {
	}

	private static JAXBContext jc;
	private static Schema schema;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws SAXException {
		if (schema == null) {
			SchemaFactory sf = XmlDefinerUtils.getSecureSchemaFactory();
			List<Source> xsdSources = getXSDSources();
			schema = sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
		}
		return schema;
	}

	public static List<Source> getXSDSources() {
		List<Source> xsdSources = new ArrayList<Source>();
		xsdSources.add(new StreamSource(XmlDSigUtils.class.getResourceAsStream(XML_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(XmlDSigUtils.class.getResourceAsStream(XMLDSIG_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
