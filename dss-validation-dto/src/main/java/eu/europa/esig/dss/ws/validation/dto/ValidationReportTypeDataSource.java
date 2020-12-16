/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.validation.dto;

import eu.europa.esig.validationreport.ValidationReportFacade;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import javax.activation.DataSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Represents an ETSI Validation Report data source
 */
public class ValidationReportTypeDataSource implements DataSource {

	/** The ETSI Validation report */
	private final ValidationReportType validationReport;

	/**
	 * Default constructor
	 *
	 * @param validationReport {@link ValidationReportType}
	 */
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
