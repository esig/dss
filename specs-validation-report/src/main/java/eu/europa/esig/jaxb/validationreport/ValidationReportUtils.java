package eu.europa.esig.jaxb.validationreport;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.jaxb.trustedlist.TrustedListUtils;
import eu.europa.esig.jaxb.xades.XAdESUtils;

public final class ValidationReportUtils {

	public static final String VALIDATION_REPORT_SCHEMA_LOCATION = "/xsd/1910202xmlSchema.xsd";

	private ValidationReportUtils() {
	}

	private static JAXBContext jc;
	private static Schema schema;

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

	public static Schema getSchema() {
		if (schema == null) {
			try (InputStream isXsdXAdES = ValidationReportUtils.class.getResourceAsStream(XAdESUtils.XADES_SCHEMA_LOCATION);
					InputStream isXsdTrustedList = ValidationReportUtils.class.getResourceAsStream(TrustedListUtils.TRUSTED_LIST_SCHEMA_LOCATION);
					InputStream isXsdValidationReport = ValidationReportUtils.class.getResourceAsStream(VALIDATION_REPORT_SCHEMA_LOCATION)) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				schema = sf.newSchema(new Source[] { new StreamSource(isXsdXAdES), new StreamSource(isXsdTrustedList), new StreamSource(isXsdValidationReport) });
			} catch (IOException | SAXException e) {
				throw new RuntimeException("Unable to initialize the Schema", e);
			}
		}
		return schema;
	}

}
