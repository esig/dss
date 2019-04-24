package eu.europa.esig.jaxb.validationreport;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

public final class ValidationReportUtils {

	private ValidationReportUtils() {
	}

	private static JAXBContext jc;

	public static JAXBContext getJAXBContext() {
		if (jc == null) {
			try {
				jc = JAXBContext.newInstance(ObjectFactory.class);
			} catch (JAXBException e) {
				throw new RuntimeException("Unable to initialize the JAXBContext", e);
			}
		}
		return jc;
	}

}
