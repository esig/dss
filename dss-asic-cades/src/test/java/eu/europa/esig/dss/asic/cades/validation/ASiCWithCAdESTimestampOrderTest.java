package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class ASiCWithCAdESTimestampOrderTest extends PKIFactoryAccess {
	
	@Test
	public void asicsTest() {
		validate(new FileDocument("src/test/resources/validation/dss1984.asics"));
	}
	
	@Test
	public void asiceTest() {
		validate(new FileDocument("src/test/resources/validation/dss1984.asice"));
	}
	
	public void validate(DSSDocument document) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampList.get(0).getType());
		assertEquals(TimestampType.ARCHIVE_TIMESTAMP, timestampList.get(1).getType());
		
		TimestampWrapper signatureTimestamp = timestampList.get(0);
		List<String> coveredIds = signatureTimestamp.getTimestampedObjects().stream().map(obj -> obj.getToken().getId()).collect(Collectors.toList());
		int coveredData = signatureTimestamp.getTimestampedCertificates().size() + signatureTimestamp.getTimestampedSignedData().size();
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		assertNotNull(etsiValidationReport.getSignatureValidationObjects());
		assertNotNull(etsiValidationReport.getSignatureValidationObjects().getValidationObject());
		
		int timestampedDataCounter = 0;
		for (ValidationObjectType validationObject : etsiValidationReport.getSignatureValidationObjects().getValidationObject()) {
			if (coveredIds.contains(validationObject.getId())) {
				POEType poe = validationObject.getPOE();
				assertNotNull(poe);
				assertNotNull(poe.getTypeOfProof());
				assertEquals(signatureTimestamp.getProductionTime(), poe.getPOETime());
				assertNotNull(poe.getPOEObject());
				assertNotNull(poe.getPOEObject().getVOReference());
				assertEquals(1, poe.getPOEObject().getVOReference().size());
				Object poeObject = poe.getPOEObject().getVOReference().get(0);
				assertTrue(poeObject instanceof ValidationObjectType);
				assertEquals(signatureTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
				
				++timestampedDataCounter;
			}
		}
		assertEquals(coveredData, timestampedDataCounter);
		
	}

	@Override
	protected String getSigningAlias() {
		// TODO Auto-generated method stub
		return null;
	}

}
