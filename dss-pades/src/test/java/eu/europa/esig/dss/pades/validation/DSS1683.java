package eu.europa.esig.dss.pades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1683 extends PKIFactoryAccess {
	
	@Test
	public void test() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-1683.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		// reports.print();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		
		XmlDigestMatcher xmlDigestMatcher = signature.getDigestMatchers().get(0);
		assertEquals(DigestMatcherType.CONTENT_DIGEST, xmlDigestMatcher.getType());
		assertNotNull(xmlDigestMatcher.getDigestMethod());
		assertNotNull(xmlDigestMatcher.getDigestValue());
		assertTrue(xmlDigestMatcher.isDataFound());
		assertTrue(xmlDigestMatcher.isDataIntact());
		
		assertTrue(signature.isSignatureIntact());
		assertTrue(signature.isSignatureValid());
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBasicBuildingBlock.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
