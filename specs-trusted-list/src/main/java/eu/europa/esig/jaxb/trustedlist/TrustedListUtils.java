package eu.europa.esig.jaxb.trustedlist;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import eu.europa.esig.jaxb.xmldsig.ObjectFactory;

public final class TrustedListUtils {

	private TrustedListUtils() {
	}

	private static JAXBContext jc;

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

}
