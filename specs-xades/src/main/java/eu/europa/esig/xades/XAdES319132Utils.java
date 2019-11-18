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

public final class XAdES319132Utils extends XSDAbstractUtils {
	
	private static final XmlDSigUtils xmlDSigUtils = XmlDSigUtils.newInstance();
	
	public static final String XADES_SCHEMA_LOCATION_EN_319_132 = "/xsd/XAdES01903v132-201601.xsd";
	public static final String XADES_141_SCHEMA_LOCATION_EN_319_132 = "/xsd/XAdES01903v141-201601.xsd";

	private static JAXBContext jc;
	private static Schema schema;
	
	private static XAdES319132Utils xades319132Utils;

	private XAdES319132Utils() {
	}
	
	public static XAdES319132Utils newInstance() {
		if (xades319132Utils == null) {
			xades319132Utils = new XAdES319132Utils();
		}
		return xades319132Utils;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class);
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
		xsdSources.add(new StreamSource(XAdES319132Utils.class.getResourceAsStream(XADES_SCHEMA_LOCATION_EN_319_132)));
		xsdSources.add(new StreamSource(XAdES319132Utils.class.getResourceAsStream(XADES_141_SCHEMA_LOCATION_EN_319_132)));
		return xsdSources;
	}

}
