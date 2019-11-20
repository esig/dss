package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simpletimestampreport.SimpleTimestampReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.reports.TimestampReports;

public class ASiCEWithCAdESTimestampValidatorTest extends PKIFactoryAccess {
	
	@Test
	public void test() {

		List<DSSDocument> documentsToSign = new ArrayList<DSSDocument>();
		documentsToSign.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
		documentsToSign.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));

		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentsToSign, signatureParameters, signatureValue);
		
		ASiCWithCAdESContainerExtractor containerExtractor = new ASiCWithCAdESContainerExtractor(signedDocument);
		ASiCExtractResult asicExtractResult = containerExtractor.extract();
		List<DSSDocument> timestampDocuments = asicExtractResult.getTimestampDocuments();
		assertEquals(1, timestampDocuments.size());
		DSSDocument archiveTimestamp = timestampDocuments.get(0);
		
		List<DSSDocument> archiveManifestDocuments = asicExtractResult.getArchiveManifestDocuments();
		assertEquals(1, archiveManifestDocuments.size());
		DSSDocument archiveManifest = archiveManifestDocuments.get(0);
		
		ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(archiveManifest);
		assertNotNull(manifestFile);
		
		ASiCEWithCAdESManifestValidator asiceWithCAdESManifestValidator = new ASiCEWithCAdESManifestValidator(manifestFile, asicExtractResult.getAllDocuments());
		asiceWithCAdESManifestValidator.validateEntries();
		
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		
		ASiCEWithCAdESTimestampValidator asiceWithCAdESTimestampValidator = new ASiCEWithCAdESTimestampValidator(
				archiveTimestamp, archiveManifest, TimestampType.ARCHIVE_TIMESTAMP, manifestFile, certificateVerifier.createValidationPool());
		asiceWithCAdESTimestampValidator.setCertificateVerifier(certificateVerifier);
		
		TimestampReports reports = asiceWithCAdESTimestampValidator.validate();

		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getXmlSimpleReport());
		
		DetailedReport detailedReport = reports.getDetailedReport();
		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(1, timestampIds.size());
		String timestampId = timestampIds.get(0);
		assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(timestampId));
		
		XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);
		assertNotNull(timestampBBB.getCertificateChain());
		assertEquals(2, timestampBBB.getCertificateChain().getChainItem().size());
		assertEquals(Indication.PASSED, timestampBBB.getConclusion().getIndication());
		
		assertTrue(Utils.isCollectionEmpty(timestampBBB.getConclusion().getErrors()));
		assertTrue(Utils.isCollectionEmpty(timestampBBB.getConclusion().getWarnings()));
		assertTrue(Utils.isCollectionEmpty(timestampBBB.getConclusion().getInfos()));
		
		SimpleTimestampReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport.getTimestamp());
		assertNotNull(simpleReport.getTimestampId());
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getCertificateChain()));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getCertificateChainIds()));
		assertNotNull(simpleReport.getProducedBy());
		assertNotNull(simpleReport.getProductionTime());
		assertNotNull(simpleReport.getValidationTime());
		assertTrue(Utils.isCollectionEmpty(simpleReport.getErrors()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getWarnings()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getInfos()));
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
