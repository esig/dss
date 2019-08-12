package eu.europa.esig.dss.ws.signature.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.signature.XAdESService;

public abstract class AbstractRemoteSignatureServiceTest extends PKIFactoryAccess {
	
	protected XAdESService getXAdESService() {
		XAdESService xadesService = new XAdESService(getCompleteCertificateVerifier());
		xadesService.setTspSource(getGoodTsa());
		return xadesService;
	}
	
	protected ASiCWithXAdESService getASiCXAdESService() {
		ASiCWithXAdESService asicService = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		asicService.setTspSource(getGoodTsa());
		return asicService;
	}
	
	protected void validate(DSSDocument doc, List<DSSDocument> detachedContents) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(detachedContents);
		
		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
