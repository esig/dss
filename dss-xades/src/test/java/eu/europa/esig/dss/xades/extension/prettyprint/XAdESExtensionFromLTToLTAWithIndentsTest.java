package eu.europa.esig.dss.xades.extension.prettyprint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESExtensionFromLTToLTAWithIndentsTest extends PKIFactoryAccess {
	
	protected XAdESService service;
	protected XAdESSignatureParameters signatureParameters;
	
	@Test
	public void test() throws Exception {
		DSSDocument originalDocument = new FileDocument(new File("src/test/resources/sample.xml"));
		DSSDocument signedDocument = getSignedDocument(originalDocument);
		// signedDocument.save("target/signedDoc.xml");
		
		DSSDocument signedWithIndents = addCustomIndents(signedDocument);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedWithIndents);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(getOriginalSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		DSSDocument extendedDocument = service.extendDocument(signedWithIndents, getExtensionParameters());
		// extendedDocument.save("target/fileWithIndentsToLTA.xml");
		
		validateDocument(extendedDocument);
	}

	private DSSDocument getSignedDocument(DSSDocument doc) {
		// Sign
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		signatureParameters.setPrettyPrint(true);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	private XAdESSignatureParameters getExtensionParameters() {
		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		extensionParameters.setPrettyPrint(true);
		return extensionParameters;
	}

	private SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LT;
	}

	private SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LTA;
	}
	
	private DSSDocument addCustomIndents(DSSDocument document) {
		Document documentDom = DomUtils.buildDOM(document);
		Node unsignedSignaturePropertiesNode = DomUtils.getNode(documentDom, "//xades:UnsignedSignatureProperties");
		Text customIndents = documentDom.createTextNode("\n\t\n\t\t\n\t\t\t\n\t\t\t\n\t\t\n\t\n\n\n\n");
		Node firstChild = getFirstElement(unsignedSignaturePropertiesNode);
		unsignedSignaturePropertiesNode.insertBefore(customIndents, firstChild);
		
		Text customIndentsClone = documentDom.createTextNode("\n\t\n\t\t\n\t\t\t\n\t\t\t\n\t\t\n\t\n\n\n\n");
		firstChild.insertBefore(customIndentsClone, getFirstElement(firstChild));
		return DomUtils.createDssDocumentFromDomDocument(documentDom, "signedDocWithIndents");
	}
	
	private Node getFirstElement(Node node) {
		NodeList childNodes = node.getChildNodes();
		for (int ii = 0; ii < childNodes.getLength(); ii++) {
			Node item = childNodes.item(ii);
			if (Node.ELEMENT_NODE == item.getNodeType()) {
				return item;
			}
		}
		return null;
	}
	
	private void validateDocument(DSSDocument document) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		checkTimestamps(diagnosticData);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		validateDetailedReport(detailedReport);
		assertEquals(SignatureLevel.XAdES_BASELINE_LTA.toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	private void checkTimestamps(DiagnosticData diagnosticData) {
		Set<TimestampWrapper> allTimestamps = diagnosticData.getTimestampSet();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			assertNotNull(timestampWrapper.getProductionTime());
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureIntact());
			assertTrue(timestampWrapper.isSignatureValid());

			List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
			for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
				assertTrue(xmlDigestMatcher.isDataFound());
				assertTrue(xmlDigestMatcher.isDataIntact());
			}
		}
	}
	
	private void validateDetailedReport(DetailedReport detailedReport) {
		assertNotNull(detailedReport);

		int nbBBBs = detailedReport.getBasicBuildingBlocksNumber();
		assertTrue(nbBBBs > 0);
		for (int i = 0; i < nbBBBs; i++) {
			String id = detailedReport.getBasicBuildingBlocksSignatureId(i);
			assertNotNull(id);
			assertNotNull(detailedReport.getBasicBuildingBlocksIndication(id));
		}

		List<String> signatureIds = detailedReport.getSignatureIds();
		assertTrue(Utils.isCollectionNotEmpty(signatureIds));
		for (String sigId : signatureIds) {
			Indication basicIndication = detailedReport.getBasicValidationIndication(sigId);
			assertNotNull(basicIndication);
			assertFalse(Indication.FAILED.equals(basicIndication));
			if (!Indication.PASSED.equals(basicIndication)) {
				assertNotNull(detailedReport.getBasicValidationSubIndication(sigId));
			}
		}

		List<String> timestampIds = detailedReport.getTimestampIds();
		if (Utils.isCollectionNotEmpty(timestampIds)) {
			for (String tspId : timestampIds) {
				Indication timestampIndication = detailedReport.getTimestampValidationIndication(tspId);
				assertNotNull(timestampIndication);
				assertFalse(Indication.FAILED.equals(timestampIndication));
				if (!Indication.PASSED.equals(timestampIndication)) {
					assertNotNull(detailedReport.getTimestampValidationSubIndication(tspId));
				}
			}
		}

		for (String sigId : signatureIds) {
			Indication ltvIndication = detailedReport.getLongTermValidationIndication(sigId);
			assertNotNull(ltvIndication);
			assertFalse(Indication.FAILED.equals(ltvIndication));
			if (!Indication.PASSED.equals(ltvIndication)) {
				assertNotNull(detailedReport.getLongTermValidationSubIndication(sigId));
			}
		}

		for (String sigId : signatureIds) {
			Indication archiveDataIndication = detailedReport.getArchiveDataValidationIndication(sigId);
			assertNotNull(archiveDataIndication);
			assertFalse(Indication.FAILED.equals(archiveDataIndication));
			if (!Indication.PASSED.equals(archiveDataIndication)) {
				assertNotNull(detailedReport.getArchiveDataValidationSubIndication(sigId));
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
