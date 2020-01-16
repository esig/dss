package eu.europa.esig.dss.pades.timestamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBTest;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.ValidationConstraintsEvaluationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

public abstract class AbstractPAdESTimestampTest extends PKIFactoryAccess {

	@Test
	public void test() {
		
		DSSDocument documentToTimestamp = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/sample.pdf"));
		
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		DSSDocument timestampedDoc = service.timestamp(documentToTimestamp, new PAdESSignatureParameters());
		assertNotNull(timestampedDoc);
		assertNotNull(timestampedDoc.getMimeType());
		assertNotNull(timestampedDoc.getName());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(timestampedDoc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(0, diagnosticData.getSignatures().size());
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);
		assertTrue(timestampWrapper.isMessageImprintDataFound());
		assertTrue(timestampWrapper.isMessageImprintDataIntact());
		assertTrue(timestampWrapper.isSignatureIntact());
		assertTrue(timestampWrapper.isSignatureValid());

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
		return null;
	}

}
