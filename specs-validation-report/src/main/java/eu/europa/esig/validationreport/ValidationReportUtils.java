package eu.europa.esig.validationreport;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.trustedlist.TrustedListUtils;
import eu.europa.esig.validationreport.jaxb.ObjectFactory;

public final class ValidationReportUtils {

	public static final String VALIDATION_REPORT_SCHEMA_LOCATION = "/xsd/1910202xmlSchema.xsd";

	private ValidationReportUtils() {
	}

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	private static JAXBContext jc;
	private static Schema schema;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws SAXException {
		if (schema == null) {
			SchemaFactory sf = XmlDefinerUtils.getSecureSchemaFactory();
			List<Source> xsdSources = getXSDSources();
			schema = sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
		}
		return schema;
	}

	public static List<Source> getXSDSources() {
		List<Source> xsdSources = TrustedListUtils.getXSDSources();
		xsdSources.add(new StreamSource(ValidationReportUtils.class.getResourceAsStream(VALIDATION_REPORT_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
