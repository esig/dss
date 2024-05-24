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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ExtendXAdESBWithoutSignedDataObjectPropertiesToTTest extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		DSSDocument toSignDocument = new FileDocument("src/test/resources/XAdESBWithoutSignedDataObjectProperties.xml");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toSignDocument);
		CertificateToken signingCertificateToken = validator.getSignatures().get(0).getSigningCertificateToken();

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(signingCertificateToken.getNotAfter());
		calendar.add(Calendar.MONTH, -1);
		Date tstTime = calendar.getTime();

		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);
		service.setTspSource(getGoodTsaByTime(tstTime));

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		certificateVerifier.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());

		Exception exception = assertThrows(AlertException.class, () -> service.extendDocument(toSignDocument, parameters));
		assertTrue(exception.getMessage().contains("Error on signature augmentation."));
		assertTrue(exception.getMessage().contains("is expired at signing time"));

		certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());

		DSSDocument extendDocument = service.extendDocument(toSignDocument, parameters);
		// extendDocument.save("target/result.xml");

		validator = SignedDocumentValidator.fromDocument(extendDocument);

		// certificateVerifier.setDataLoader(new CommonsDataLoader());
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();
		signaturePoliciesByUrl.put("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
				new FileDocument("src/test/resources/validation/dss1135/politica_de_firma.pdf"));
		signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		String signatureId = diagnosticData.getFirstSignatureId();
		List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
		assertEquals(2, retrievedOriginalDocuments.size());
		
		assertEquals(SignatureLevel.XAdES_BASELINE_T, diagnosticData.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
