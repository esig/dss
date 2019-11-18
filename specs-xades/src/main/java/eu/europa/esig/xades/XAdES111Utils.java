package eu.europa.esig.xades;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.xmldsig.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public final class XAdES111Utils extends XSDAbstractUtils {
	
	private static final XmlDSigUtils xmlDSigUtils = XmlDSigUtils.newInstance();
	
	public static final String XADES_111_SCHEMA_LOCATION = "/xsd/XAdESv111.xsd";

	private static JAXBContext jc;
	private static Schema schema;
	
	private static XAdES111Utils xades111Utils;

	private XAdES111Utils() {
	}
	
	public static XAdES111Utils newInstance() {
		if (xades111Utils == null) {
			xades111Utils = new XAdES111Utils();
		}
		return xades111Utils;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades111.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = XmlDefinerUtils.getSchema(getXSDSources());
		}
		return schema;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = xmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdES111Utils.class.getResourceAsStream(XADES_111_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
