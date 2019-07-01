package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.DataSource;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import eu.europa.esig.jaxb.validationreport.ObjectFactory;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationReportUtils;

public class ValidationReportTypeDataSource implements DataSource {

	private final ValidationReportType validationReport;

	public ValidationReportTypeDataSource(ValidationReportType validationReport) {
		this.validationReport = validationReport;
	}

	@Override
	public String getContentType() {
		return "text/xml";
	}

	@Override
	public InputStream getInputStream() throws IOException {
		return new ByteArrayInputStream(((ByteArrayOutputStream) getOutputStream()).toByteArray());
	}

	@Override
	public String getName() {
		return "ETSIValidationReport";
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		try {
			ObjectFactory objectFactory = new ObjectFactory();
			JAXBContext jaxbContext = ValidationReportUtils.getJAXBContext();
			Marshaller marshaller = jaxbContext.createMarshaller();

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			marshaller.marshal(objectFactory.createValidationReport(validationReport), baos);
			return baos;
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

}
