package eu.europa.esig.saml;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import eu.europa.esig.xmldsig.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public class XMLEncUtils extends XSDAbstractUtils {

	public static final String XML_ENC_SCHEMA_LOCATION = "/xsd/xenc-schema.xsd";

	private static XMLEncUtils singleton;

	private JAXBContext jc;

	private XMLEncUtils() {
	}

	public static XMLEncUtils getInstance() {
		if (singleton == null) {
			singleton = new XMLEncUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmlenc.jaxb.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
		xsdSources.add(new StreamSource(XMLEncUtils.class.getResourceAsStream(XML_ENC_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
