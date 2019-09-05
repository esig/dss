package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.junit.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SATimestampType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

public class EtsiValidationReportComplete extends PKIFactoryAccess {
	
	@Test
	public void timestampTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/BG_BOR/Signature-P-BG_BOR-2.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// System.out.println(reports.getXmlValidationReport().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationType = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationType);
		SignatureAttributesType signatureAttributesType = signatureValidationType.getSignatureAttributes();
		assertNotNull(signatureAttributesType);
		List<Object> attributesList = signatureAttributesType.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		assertTrue(Utils.isCollectionNotEmpty(attributesList));
		List<SATimestampType> foundTimestamps = new ArrayList<SATimestampType>();
		int docTimestampsCounter = 0;
		int sigTimestampsCounter = 0;
		int archiveTimestampsCounter = 0;
		for (Object object : attributesList) {
			JAXBElement<?> element = (JAXBElement<?>) object;
			if (element.getValue() instanceof SATimestampType) {
				SATimestampType saTimestamp = (SATimestampType) element.getValue();
				assertTrue(Utils.isCollectionNotEmpty(saTimestamp.getAttributeObject()));
				assertNotNull(saTimestamp.getTimeStampValue());
				foundTimestamps.add(saTimestamp);
			}
			if (element.getName().getLocalPart().equals("ArchiveTimeStamp")) {
				archiveTimestampsCounter++;
			}
			if (element.getName().getLocalPart().equals("DocTimeStamp")) {
				docTimestampsCounter++;
			}
			if (element.getName().getLocalPart().equals("SignatureTimeStamp")) {
				sigTimestampsCounter++;
			}
		}
		assertEquals(2, foundTimestamps.size());
		assertEquals(1, sigTimestampsCounter);
		assertEquals(1, docTimestampsCounter);
		assertEquals(0, archiveTimestampsCounter);
	}
	
	@Test
	public void signatureIdentifierTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/BG_BOR/Signature-P-BG_BOR-2.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
		assertNotNull(signatureIdentifier);
		assertFalse(signatureIdentifier.isDocHashOnly());
		assertFalse(signatureIdentifier.isHashOnly());
		
		assertNotNull(signatureIdentifier.getSignatureValue());
		
	}
	
	@Test
	public void signerDocumentTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-5-signatures-and-1-document-timestamp.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		// System.out.println(reports.getXmlValidationReport().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
		assertEquals(5, signatureValidationReports.size());
		byte[] previousSignatureSignerDocumentDigest = null;
		for (SignatureValidationReportType signatureValidationReportType : signatureValidationReports) {
			SignersDocumentType signersDocument = signatureValidationReportType.getSignersDocument().get(0);
			assertNotNull(signersDocument);
			DigestAlgAndValueType digestAlgAndValue = signersDocument.getDigestAlgAndValue();
			assertNotNull(digestAlgAndValue);
			byte[] digestValue = digestAlgAndValue.getDigestValue();
			assertTrue(Utils.isArrayNotEmpty(digestValue));
			assertFalse(Arrays.equals(digestValue, previousSignatureSignerDocumentDigest));
			previousSignatureSignerDocumentDigest = digestValue;
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
