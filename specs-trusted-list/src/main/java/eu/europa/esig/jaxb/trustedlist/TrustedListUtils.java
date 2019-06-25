package eu.europa.esig.jaxb.trustedlist;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.jaxb.xades.XAdESUtils;
import eu.europa.esig.jaxb.xmldsig.ObjectFactory;

public final class TrustedListUtils {

	public static final String TRUSTED_LIST_SCHEMA_LOCATION = "/xsd/ts_119612v020101_xsd.xsd";
	public static final String TRUSTED_LIST_SIE_SCHEMA_LOCATION = "/xsd/ts_119612v020101_sie_xsd.xsd";
	public static final String TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION = "/xsd/ts_119612v020101_additionaltypes_xsd.xsd";

	private TrustedListUtils() {
	}

	private static JAXBContext jc;
	private static Schema schema;

	public static JAXBContext getJAXBContext() {
		if (jc == null) {
			try {
				jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.jaxb.xades132.ObjectFactory.class, eu.europa.esig.jaxb.xades141.ObjectFactory.class,
						eu.europa.esig.jaxb.trustedlist.tsl.ObjectFactory.class, eu.europa.esig.jaxb.trustedlist.tslx.ObjectFactory.class, eu.europa.esig.jaxb.trustedlist.ecc.ObjectFactory.class);
			} catch (JAXBException e) {
				throw new RuntimeException("Unable to initialize the JAXBContext", e);
			}
		}
		return jc;
	}

	public static Schema getSchema() {
		if (schema == null) {
			try (InputStream isXsdXAdES = TrustedListUtils.class.getResourceAsStream(XAdESUtils.XADES_SCHEMA_LOCATION);
					InputStream isXsdXAdES141 = TrustedListUtils.class.getResourceAsStream(XAdESUtils.XADES_141_SCHEMA_LOCATION);
					InputStream isXsdTrustedList = TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SCHEMA_LOCATION);
					InputStream isXsdTrustedListSie = TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SIE_SCHEMA_LOCATION);
					InputStream isXsdTrustedListAdditionalTypes = TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION)) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				schema = sf.newSchema(new Source[] { new StreamSource(isXsdXAdES), new StreamSource(isXsdXAdES141), new StreamSource(isXsdTrustedList), new StreamSource(isXsdTrustedListSie),
						new StreamSource(isXsdTrustedListAdditionalTypes) });
			} catch (IOException | SAXException e) {
				throw new RuntimeException("Unable to initialize the Schema", e);
			}
		}
		return schema;
	}

}
