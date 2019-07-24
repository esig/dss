package eu.europa.esig.dss.ws.validation.dto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.DataSource;

import eu.europa.esig.validationreport.ValidationReportFacade;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

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
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ValidationReportFacade.newFacade().marshall(validationReport, baos, true);
			return baos;
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

}
