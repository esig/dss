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
package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PolicyZeroHashTest extends PKIFactoryAccess {

	@Test
	public void test() throws JAXBException, IOException, SAXException {

		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/TEST2_signed_with_zero_policy_hash.pdf"));
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		String signatureId = diagnosticData.getFirstSignatureId();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
		assertTrue(signatureWrapper.getPolicyStatus());
		assertTrue(signatureWrapper.isZeroHashPolicy());

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks basicBuildingBlocks = detailedReport.getBasicBuildingBlockById(signatureId);
		XmlVCI vci = basicBuildingBlocks.getVCI();
		assertNotNull(vci);
		assertEquals(Indication.PASSED, vci.getConclusion().getIndication());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
