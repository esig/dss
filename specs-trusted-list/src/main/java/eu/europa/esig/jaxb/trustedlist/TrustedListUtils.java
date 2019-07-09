package eu.europa.esig.jaxb.trustedlist;

import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.jaxb.trustedlist.tsl.ObjectFactory;
import eu.europa.esig.jaxb.xades.XAdESUtils;

public final class TrustedListUtils {

	public static final String TRUSTED_LIST_SCHEMA_LOCATION = "/xsd/ts_119612v020101_xsd.xsd";
	public static final String TRUSTED_LIST_SIE_SCHEMA_LOCATION = "/xsd/ts_119612v020101_sie_xsd.xsd";
	public static final String TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION = "/xsd/ts_119612v020101_additionaltypes_xsd.xsd";

	private TrustedListUtils() {
	}

	private static JAXBContext jc;
	private static Schema schema;
	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(eu.europa.esig.jaxb.xmldsig.ObjectFactory.class, eu.europa.esig.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.jaxb.xades141.ObjectFactory.class, ObjectFactory.class,
					eu.europa.esig.jaxb.trustedlist.tslx.ObjectFactory.class, eu.europa.esig.jaxb.trustedlist.ecc.ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws SAXException {
		if (schema == null) {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			List<Source> xsdSources = getXSDSources();
			schema = sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
		}
		return schema;
	}

	public static List<Source> getXSDSources() {
		List<Source> xsdSources = XAdESUtils.getXSDSources();
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SIE_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
