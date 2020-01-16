package eu.europa.esig.dss.pades.extension.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.ValidationConstraintsEvaluationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

public class PDFArchiveTimestampingTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws Exception {

		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		String originalDocDigestBase64 = Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, doc));
		
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		PAdESSignatureParameters extendParams = new PAdESSignatureParameters();
		
		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
		extendParams.setSigningCertificate(getSigningCert());
		DSSDocument extendedDoc = service.extendDocument(doc, extendParams);
		
		Thread.sleep(1000);
		
		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		extendParams.setSigningCertificate(getSigningCert());
		DSSDocument extendedLTADoc = service.extendDocument(extendedDoc, extendParams);
		
		PDFDocumentValidator validator = new PDFDocumentValidator(extendedLTADoc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		
//		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		
		assertEquals(0, simpleReport.getSignaturesCount());
		assertEquals(0, simpleReport.getSignatureIdList().size());
		
		assertEquals(2, simpleReport.getTimestampIdList().size());
		for (String timestampId : simpleReport.getTimestampIdList()) {
			assertEquals(Indication.PASSED, simpleReport.getIndication(timestampId));
		}
		
		DetailedReport detailedReport = reports.getDetailedReport();
		for (String timestampId : simpleReport.getTimestampIdList()) {
			assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(timestampId));
		}
		assertNull(detailedReport.getFirstSignatureId());
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		assertEquals(2, diagnosticData.getTimestampIdList().size());
		
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertEquals(TimestampType.CONTENT_TIMESTAMP, timestampWrapper.getType());

			CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
			assertNotNull(signingCertificate);
			
			List<CertificateSourceType> sources = signingCertificate.getSources();
			assertTrue(Utils.isCollectionNotEmpty(sources));
			boolean timestampSource = false;
			for (CertificateSourceType source : sources) {
				if (CertificateSourceType.TIMESTAMP.equals(source)) {
					timestampSource = true;
				}
			}
			assertTrue(timestampSource);
			
			assertEquals(1, timestampWrapper.getTimestampedSignedDataIds().size());
		}
		
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
		
		List<XmlSignerData> originalDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(2, originalDocuments.size());
		boolean fullDocFound = false;
		boolean partialDocFound = false;
		for (XmlSignerData signerData : originalDocuments) {
			if ("Full PDF".equals(signerData.getReferencedName())) {
				fullDocFound = true;
			} else {
				assertEquals(originalDocDigestBase64, Utils.toBase64(signerData.getDigestAlgoAndValue().getDigestValue()));
				partialDocFound = true;
			}
		}
		assertTrue(fullDocFound);
		assertTrue(partialDocFound);
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
		assertNotNull(signatureValidationReports);
		assertEquals(1, signatureValidationReports.size());
		SignatureValidationReportType signatureValidationReport = signatureValidationReports.get(0);
		ValidationStatusType signatureValidationStatus = signatureValidationReport.getSignatureValidationStatus();
		assertNotNull(signatureValidationStatus);
		assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
		
		ValidationObjectListType validationObjects = etsiValidationReport.getSignatureValidationObjects();
		assertNotNull(validationObjects);
		assertTrue(Utils.isCollectionNotEmpty(validationObjects.getValidationObject()));
		int certificatesCounter = 0;
		int revocationCounter = 0;
		int timestampCounter = 0;
		int signerDataCounter = 0;
		for (ValidationObjectType validationObject : validationObjects.getValidationObject()) {
			switch (validationObject.getObjectType()) {
				case CERTIFICATE:
					++certificatesCounter;
					break;
				case CRL:
				case OCSP_RESPONSE:
					++revocationCounter;
					break;
				case TIMESTAMP:
					++timestampCounter;
					break;
				case SIGNED_DATA:
					++signerDataCounter;
					break;
				default:
					break;
			}
		}
		assertEquals(diagnosticData.getUsedCertificates().size(), certificatesCounter);
		assertEquals(diagnosticData.getAllRevocationData().size(), revocationCounter);
		assertEquals(diagnosticData.getTimestampList().size(), timestampCounter);
		assertEquals(diagnosticData.getOriginalSignerDocuments().size(), signerDataCounter);
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReportJaxb);
		boolean noTimestamp = true;
		for (ValidationObjectType validationObject : etsiValidationReportJaxb.getSignatureValidationObjects().getValidationObject()) {
			if (ObjectType.TIMESTAMP == validationObject.getObjectType()) {
				noTimestamp = false;
				POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
				assertNotNull(poeProvisioning);
				assertNotNull(poeProvisioning.getPOETime());
				assertTrue(Utils.isCollectionNotEmpty(poeProvisioning.getValidationObject()));

				SignatureValidationReportType validationReport = validationObject.getValidationReport();
				assertNotNull(validationReport);
				assertNotNull(validationReport.getSignatureQuality());
				assertTrue(Utils.isCollectionNotEmpty(validationReport.getSignatureQuality().getSignatureQualityInformation()));

				SignerInformationType signerInformation = validationReport.getSignerInformation();
				assertNotNull(signerInformation);
				assertNotNull(signerInformation.getSigner());
				assertNotNull(signerInformation.getSignerCertificate());

				ValidationStatusType timestampValidationStatus = validationReport.getSignatureValidationStatus();
				assertNotNull(timestampValidationStatus);
				assertNotNull(timestampValidationStatus.getMainIndication());
				assertNotNull(timestampValidationStatus.getAssociatedValidationReportData());
				assertNotNull(timestampValidationStatus.getAssociatedValidationReportData().get(0).getCryptoInformation());

				ValidationConstraintsEvaluationReportType validationConstraintsEvaluationReport = validationReport.getValidationConstraintsEvaluationReport();
				assertNotNull(validationConstraintsEvaluationReport);
				assertTrue(Utils.isCollectionNotEmpty(validationConstraintsEvaluationReport.getValidationConstraint()));
			}
		}
		assertFalse(noTimestamp);

	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
