package eu.europa.esig.saml;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import eu.europa.esig.xmldsig.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public class SAMLAssertionUtils extends XSDAbstractUtils {

	public static final String SAML_ASSERTION_SCHEMA_LOCATION = "/xsd/saml-schema-assertion-2.0.xsd";
	public static final String SAML_DCE_SCHEMA_LOCATION = "/xsd/saml-schema-dce-2.0.xsd";
	public static final String SAML_ECP_SCHEMA_LOCATION = "/xsd/saml-schema-ecp-2.0.xsd";
	public static final String SAML_METADATA_SCHEMA_LOCATION = "/xsd/saml-schema-metadata-2.0.xsd";
	public static final String SAML_PROTOCOL_SCHEMA_LOCATION = "/xsd/saml-schema-protocol-2.0.xsd";
	public static final String SAML_X500_SCHEMA_LOCATION = "/xsd/saml-schema-x500-2.0.xsd";
	public static final String SAML_XACML_SCHEMA_LOCATION = "/xsd/saml-schema-xacml-2.0.xsd";
	public static final String SAML_AUTHN_CONTEXT_TYPES_SCHEMA_LOCATION = "/xsd/saml-schema-authn-context-types-2.0.xsd";

	private static SAMLAssertionUtils singleton;

	private JAXBContext jc;

	private SAMLAssertionUtils() {
	}

	public static SAMLAssertionUtils getInstance() {
		if (singleton == null) {
			singleton = new SAMLAssertionUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmlenc.jaxb.ObjectFactory.class,
					eu.europa.esig.soap.jaxb.envelope.ObjectFactory.class, eu.europa.esig.saml.jaxb.assertion.ObjectFactory.class,
					eu.europa.esig.saml.jaxb.authn.context.ObjectFactory.class, eu.europa.esig.saml.jaxb.dce.ObjectFactory.class,
					eu.europa.esig.saml.jaxb.ecp.ObjectFactory.class, eu.europa.esig.saml.jaxb.protocol.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
		xsdSources.addAll(XMLEncUtils.getInstance().getXSDSources());
		xsdSources.addAll(SoapEnvelopeUtils.getInstance().getXSDSources());
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_ASSERTION_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_PROTOCOL_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_AUTHN_CONTEXT_TYPES_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_DCE_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_ECP_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_METADATA_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_X500_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_XACML_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
