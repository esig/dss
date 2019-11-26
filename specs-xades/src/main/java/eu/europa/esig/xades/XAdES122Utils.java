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

public final class XAdES122Utils extends XSDAbstractUtils {
	
	private static final XmlDSigUtils xmlDSigUtils = XmlDSigUtils.newInstance();
	
	public static final String XADES_122_SCHEMA_LOCATION = "/xsd/XAdESv122.xsd";

	private static JAXBContext jc;
	private static Schema schema;
	
	private static XAdES122Utils xades122Utils;

	private XAdES122Utils() {
	}
	
	public static XAdES122Utils newInstance() {
		if (xades122Utils == null) {
			xades122Utils = new XAdES122Utils();
		}
		return xades122Utils;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades122.ObjectFactory.class);
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
		xsdSources.add(new StreamSource(XAdES122Utils.class.getResourceAsStream(XADES_122_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
