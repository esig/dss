package eu.europa.esig.xades;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public final class XAdESUtils {

	public static final String XADES_111_SCHEMA_LOCATION = "/xsd/XAdESv111.xsd";
	public static final String XADES_122_SCHEMA_LOCATION = "/xsd/XAdESv122.xsd";
	public static final String XADES_SCHEMA_LOCATION = "/xsd/XAdES.xsd";
	public static final String XADES_141_SCHEMA_LOCATION = "/xsd/XAdESv141.xsd";
	public static final String XADES_SCHEMA_LOCATION_EN_319_132 = "/xsd/XAdES01903v132-201601.xsd";
	public static final String XADES_141_SCHEMA_LOCATION_EN_319_132 = "/xsd/XAdES01903v141-201601.xsd";

	private XAdESUtils() {
	}

	private static JAXBContext jc;
	private static Schema schema;
	private static Schema schemaETSIEN319132;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = getSchema(getXSDSources());
		}
		return schema;
	}

	public static Schema getSchemaETSI_EN_319_132() throws SAXException {
		if (schemaETSIEN319132 == null) {
			schemaETSIEN319132 = getSchema(getXSDSourcesETSI_EN_319_132());
		}
		return schemaETSIEN319132;
	}

	private static Schema getSchema(List<Source> xsdSources) throws SAXException {
		SchemaFactory sf = XmlDefinerUtils.getSecureSchemaFactory();
		return sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
	}

	public static List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_141_SCHEMA_LOCATION)));
		return xsdSources;
	}

	public static List<Source> getXSDSourcesETSI_EN_319_132() {
		List<Source> xsdSources = XmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_SCHEMA_LOCATION_EN_319_132)));
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_141_SCHEMA_LOCATION_EN_319_132)));
		return xsdSources;
	}

}
