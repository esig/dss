/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.simplereport;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SimpleReportFacadeTest {

	@Test
	void test() throws Exception {
		createAndValidate("sr1.xml");
	}

	@Test
	void test2() throws Exception {
		createAndValidate("sr2.xml");
	}

	@Test
	void pdfaTest() throws Exception {
		createAndValidate("sr-pades.xml");
	}

	@Test
	void sigAndTstTest() throws Exception {
		createAndValidate("sr-sig-and-tst.xml");
	}
	
	@Test
	void generateSemantics() throws Exception {
		createAndValidate("sr-semantics.xml");
	}

	private void createAndValidate(String filename) throws Exception {
		SimpleReportFacade facade = SimpleReportFacade.newFacade();

		XmlSimpleReport simpleReport = facade.unmarshall(new File("src/test/resources/" + filename));
		assertNotNull(simpleReport);
		String simpleReportString = facade.marshall(simpleReport);

		String htmlReport = facade.generateHtmlReport(simpleReport);
		assertNotNull(htmlReport);

		assertNotNull(facade.generateHtmlReport(simpleReportString));
	}

}
