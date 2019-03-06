package eu.europa.esig.jaxb.trustedlist;

import java.io.File;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.jaxb.xmldsig.ObjectFactory;

public final class TrustedListUtils {

	private TrustedListUtils() {
	}

	private static JAXBContext jc;
	private static Schema schema;

	public static JAXBContext getJAXBContext() {
		if (jc == null) {
			try {
				jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.jaxb.xades132.ObjectFactory.class,
						eu.europa.esig.jaxb.xades141.ObjectFactory.class, eu.europa.esig.jaxb.trustedlist.tsl.ObjectFactory.class,
						eu.europa.esig.jaxb.trustedlist.tslx.ObjectFactory.class, eu.europa.esig.jaxb.trustedlist.ecc.ObjectFactory.class);
			} catch (JAXBException e) {
				throw new RuntimeException("Unable to initialize the JAXBContext", e);
			}
		}
		return jc;
	}

	public static Schema getSchema() {
		if (schema == null) {
			try {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				schema = sf.newSchema(new Source[] { new StreamSource(new File("src/main/resources/xsd/ts_119612v020101_additionaltypes_xsd.xsd")),
						new StreamSource(new File("src/main/resources/xsd/ts_119612v020101_sie_xsd.xsd")),
						new StreamSource(new File("src/main/resources/xsd/ts_119612v020201_201601xsd.xsd")) });
			} catch (SAXException e) {
				throw new RuntimeException("Unable to initialize the Schema", e);
			}
		}
		return schema;
	}

}
