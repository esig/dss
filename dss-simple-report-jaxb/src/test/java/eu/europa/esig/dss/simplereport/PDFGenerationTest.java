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
package eu.europa.esig.dss.simplereport;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.FopFactoryBuilder;
import org.apache.fop.apps.MimeConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.xml.transform.Result;
import javax.xml.transform.sax.SAXResult;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PDFGenerationTest {

	private static FopFactory fopFactory;
	private static FOUserAgent foUserAgent;

	@BeforeAll
	public static void init() throws Exception {
		FopFactoryBuilder builder = new FopFactoryBuilder(new File(".").toURI());
		builder.setAccessibility(true);

		fopFactory = builder.build();

		foUserAgent = fopFactory.newFOUserAgent();
		foUserAgent.setCreator("DSS");
		foUserAgent.setAccessibility(true);
	}

	@Test
	public void generateSimpleReport() throws Exception {
		createAndValidate("sr1.xml");
	}

	@Test
	public void generateSimpleReport2() throws Exception {
		createAndValidate("sr2.xml");
	}

	@Test
	public void generatePdfaSimpleReport() throws Exception {
		createAndValidate("sr-pades.xml");
	}

	@Test
	public void generateSigAndTstSimpleReport() throws Exception {
		createAndValidate("sr-sig-and-tst.xml");
	}

	@Test
	public void generateSemantics() throws Exception {
		createAndValidate("sr-semantics.xml");
	}
	
	private void createAndValidate(String filename) throws Exception {
		SimpleReportFacade facade = SimpleReportFacade.newFacade();

		File file = new File("src/test/resources/" + filename);
		XmlSimpleReport simpleReport = facade.unmarshall(file);
		String simpleReportString = facade.marshall(simpleReport);

		try (FileOutputStream fos = new FileOutputStream("target/report.pdf")) {
			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(simpleReport, result);
		}
		
		File pdfReport = new File("target/report.pdf");
		assertTrue(pdfReport.exists());
		assertTrue(pdfReport.delete(), "Cannot delete PDF document (IO error)");
		assertFalse(pdfReport.exists());

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, baos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(simpleReportString, result);
			assertTrue(baos.toByteArray().length >= 0);
		}

	}

}
