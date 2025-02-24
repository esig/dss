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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractRemoteSignatureServiceTest extends PKIFactoryAccess {
	
	protected XAdESService getXAdESService() {
		XAdESService xadesService = new XAdESService(getCompleteCertificateVerifier());
		xadesService.setTspSource(getGoodTsa());
		return xadesService;
	}
	
	protected CAdESService getCAdESService() {
		CAdESService cadesService = new CAdESService(getCompleteCertificateVerifier());
		cadesService.setTspSource(getGoodTsa());
		return cadesService;
	}
	
	protected PAdESService getPAdESService() {
		PAdESService padesService = new PAdESService(getCompleteCertificateVerifier());
		padesService.setTspSource(getGoodTsa());
		padesService.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		return padesService;
	}
	
	protected JAdESService getJAdESService() {
		JAdESService jadesService = new JAdESService(getCompleteCertificateVerifier());
		jadesService.setTspSource(getGoodTsa());
		return jadesService;
	}
	
	protected ASiCWithXAdESService getASiCXAdESService() {
		ASiCWithXAdESService asicWithXadesService = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		asicWithXadesService.setTspSource(getGoodTsa());
		return asicWithXadesService;
	}
	
	protected ASiCWithCAdESService getASiCCAdESService() {
		ASiCWithCAdESService asicWithCadesService = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		asicWithCadesService.setTspSource(getGoodTsa());
		return asicWithCadesService;
	}
	
	protected DiagnosticData validate(DSSDocument doc, List<DSSDocument> detachedContents) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(detachedContents);
		
		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		if (Utils.isCollectionNotEmpty(simpleReport.getSignatureIdList())) {
			assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		} 
		if (Utils.isCollectionNotEmpty(simpleReport.getTimestampIdList())) {
			assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getTimestampIdList().get(0)));
		}
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
			assertNotNull(signatureWrapper);
			assertTrue(signatureWrapper.isSignatureIntact());
			assertTrue(signatureWrapper.isSignatureValid());
			assertTrue(signatureWrapper.isStructuralValidationValid());
		}
		return diagnosticData;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
