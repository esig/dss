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
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CustomProcessExecutorTest extends AbstractProcessExecutorTest {

	@Test
	void diagDataNotNull() throws Exception {
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(null);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(new Date());

		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The diagnostic data is missing", exception.getMessage());
	}

	@Test
	void validationPolicyNotNull() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag-data/DSS-1330-diag-data.xml"));

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(null);
		executor.setCurrentTime(new Date());

		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The validation policy is missing", exception.getMessage());
	}

	@Test
	void currentDateNotNull() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag-data/DSS-1330-diag-data.xml"));

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(null);
		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The current time is missing", exception.getMessage());
	}

	@Test
	void validationLevelNotNull() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag-data/DSS-1330-diag-data.xml"));

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(new Date());
		executor.setValidationLevel(null);

		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The validation level is missing", exception.getMessage());
	}

}
