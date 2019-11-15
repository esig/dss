package eu.europa.esig.xades;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import eu.europa.esig.xmldsig.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public abstract class XAdESAbstractUtils extends XSDAbstractUtils {
	
	protected static final String XADES_SCHEMA_LOCATION = "/xsd/XAdES.xsd";
	
	protected static final XmlDSigUtils xmlDSigUtils = XmlDSigUtils.newInstance();
	
	protected static JAXBContext jc;

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class);
		}
		return jc;
	}

}
