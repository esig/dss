package eu.europa.esig.trustedlist;

import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class TrustedListFacade extends AbstractJaxbFacade<TrustStatusListType> {

	public static TrustedListFacade newFacade() {
		return new TrustedListFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return TrustedListUtils.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return TrustedListUtils.getSchema();
	}

	@Override
	protected JAXBElement<TrustStatusListType> wrap(TrustStatusListType jaxbObject) {
		return TrustedListUtils.OBJECT_FACTORY.createTrustServiceStatusList(jaxbObject);
	}

}
