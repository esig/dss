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
package eu.europa.esig.dss.detailedreport;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class DetailedReportFacadeTest {

	@Test
	void test() throws Exception {
		createAndValidate("dr1.xml");
	}

	@Test
	void test2() throws Exception {
		createAndValidate("dr2.xml");
	}

	@Test
	void tstTest() throws Exception {
		createAndValidate("dr-tst.xml");
	}

	@Test
	void certTest() throws Exception {
		createAndValidate("dr-cert.xml");
	}

	@Test
	void sigAndTstTest() throws Exception {
		createAndValidate("dr-sig-and-tst.xml");
	}
	
	private void createAndValidate(String filename) throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		XmlDetailedReport detailedReport = facade.unmarshall(new File("src/test/resources/" + filename));
		assertNotNull(detailedReport);

		String detailedReportString = facade.marshall(detailedReport);

		String htmlReport = facade.generateHtmlReport(detailedReport);
		assertNotNull(htmlReport);

		assertNotNull(facade.generateHtmlReport(detailedReportString));
	}

}
