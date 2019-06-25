package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DigestMatcherType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

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
