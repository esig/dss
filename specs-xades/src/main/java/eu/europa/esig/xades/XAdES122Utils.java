package eu.europa.esig.xades;

import java.util.List;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;

public final class XAdES122Utils extends XAdESAbstractUtils {
	
	private static Schema schema;
	
	public static final String XADES_122_SCHEMA_LOCATION = "/xsd/XAdESv122.xsd";
	
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
	public Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = XmlDefinerUtils.getSchema(getXSDSources());
		}
		return schema;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = xmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_122_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
