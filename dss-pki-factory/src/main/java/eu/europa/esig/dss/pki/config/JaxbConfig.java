package eu.europa.esig.dss.pki.config;



import eu.europa.esig.dss.pki.ObjectFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;


public class JaxbConfig {


	public Unmarshaller unmarshaller() throws JAXBException {
		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		return jaxbContext.createUnmarshaller();
	}
//	@Bean
//	public Unmarshaller unmarshaller() {
//		Jaxb2Marshaller jaxb2Marshaller = new Jaxb2Marshaller();
//		jaxb2Marshaller.setClassesToBeBound(ObjectFactory.class);
//		return jaxb2Marshaller;
//	}

}
