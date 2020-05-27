package eu.europa.esig.saml;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import eu.europa.esig.xmldsig.XSDAbstractUtils;

public class SoapEnvelopeUtils extends XSDAbstractUtils {

	public static final String XML_SOAP_SCHEMA_LOCATION = "/xsd/schemas.xmlsoap.org.xsd";

	private static SoapEnvelopeUtils singleton;

	private JAXBContext jc;

	private SoapEnvelopeUtils() {
	}

	public static SoapEnvelopeUtils getInstance() {
		if (singleton == null) {
			singleton = new SoapEnvelopeUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(eu.europa.esig.soap.jaxb.envelope.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = new ArrayList<>();
		xsdSources.add(new StreamSource(SoapEnvelopeUtils.class.getResourceAsStream(XML_SOAP_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
