package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.junit.Test;
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
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PolicyZeroHash extends PKIFactoryAccess {

	@Test
	public void test() throws JAXBException, IOException, SAXException {

		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/TEST2_signed_with_zero_policy_hash.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
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
