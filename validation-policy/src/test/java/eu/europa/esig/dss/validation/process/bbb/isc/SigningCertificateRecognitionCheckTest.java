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
package eu.europa.esig.dss.validation.process.bbb.isc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.validation.process.bbb.LoadPolicyUtils;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.SigningCertificateRecognitionCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateRecognitionCheckTest {

	@Test
	public void signingCertificateRecognitionCheck() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/it.xml");
		DiagnosticData diagnosticData = LoadPolicyUtils.getJAXBObjectFromString(fis, DiagnosticData.class,
				"/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		XmlSigningCertificate xsc = new XmlSigningCertificate();
		xsc.setAttributePresent(true);
		xsc.setDigestValueMatch(true);
		xsc.setDigestValuePresent(true);
		xsc.setIssuerSerialMatch(true);
		xsc.setId("79513A7C5EFA8B43C0042CAAA132226FFD959EA9AA9B9331A5BF3F6383381DBC");

		XmlSignature sig = new XmlSignature();
		sig.setSigningCertificate(xsc);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData wrapper = new eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData(
				diagnosticData);
		XmlISC result = new XmlISC();

		SigningCertificateRecognitionCheck scrc = new SigningCertificateRecognitionCheck(result,
				new SignatureWrapper(sig), wrapper, constraint);

		scrc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

	}

}
