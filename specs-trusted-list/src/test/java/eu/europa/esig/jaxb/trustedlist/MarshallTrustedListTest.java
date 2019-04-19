package eu.europa.esig.jaxb.trustedlist;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.junit.Test;

import eu.europa.esig.jaxb.trustedlist.tsl.TrustStatusListType;

public class MarshallTrustedListTest {

	@Test
	@SuppressWarnings("unchecked")
	public void lotl() throws JAXBException {

		File lotl = new File("src/test/resources/lotl.xml");

		JAXBContext jc = TrustedListUtils.getJAXBContext();
		assertNotNull(jc);

		Unmarshaller unmarshaller = jc.createUnmarshaller();

		JAXBElement<TrustStatusListType> unmarshalled = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(lotl);
		assertNotNull(unmarshalled);

		Marshaller marshaller = jc.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String lotlString = sw.toString();

		JAXBElement<TrustStatusListType> unmarshalled2 = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(new StringReader(lotlString));
		assertNotNull(unmarshalled2);

	}

	@Test
	@SuppressWarnings("unchecked")
	public void tl() throws JAXBException {

		File lotl = new File("src/test/resources/tl.xml");

		JAXBContext jc = TrustedListUtils.getJAXBContext();

		Unmarshaller unmarshaller = jc.createUnmarshaller();

		JAXBElement<TrustStatusListType> unmarshalled = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(lotl);
		assertNotNull(unmarshalled);

		Marshaller marshaller = jc.createMarshaller();

		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String tlString = sw.toString();

		JAXBElement<TrustStatusListType> unmarshalled2 = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(new StringReader(tlString));
		assertNotNull(unmarshalled2);
	}

}
