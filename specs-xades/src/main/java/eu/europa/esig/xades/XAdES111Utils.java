package eu.europa.esig.xades;

import java.util.List;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;

public final class XAdES111Utils extends XAdESAbstractUtils {
	
	private static Schema schema;
	
	public static final String XADES_111_SCHEMA_LOCATION = "/xsd/XAdESv111.xsd";
	
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
	public Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = XmlDefinerUtils.getSchema(getXSDSources());
		}
		return schema;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = xmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_111_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
