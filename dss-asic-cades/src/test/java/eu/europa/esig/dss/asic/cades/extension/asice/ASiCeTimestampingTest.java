package eu.europa.esig.dss.asic.cades.extension.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

public class ASiCeTimestampingTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws Exception {

		DSSDocument doc = new FileDocument("src/test/resources/signable/no-signature-container.sce");
		
		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		ASiCWithCAdESSignatureParameters extendParams = new ASiCWithCAdESSignatureParameters();
		
		extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		extendParams.setSigningCertificate(getSigningCert());
		extendParams.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		DSSDocument extendedDoc = service.extendDocument(doc, extendParams);
		
		DocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDoc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		
		assertEquals(0, simpleReport.getSignaturesCount());
		assertEquals(0, simpleReport.getSignatureIdList().size());
		
		assertEquals(1, simpleReport.getTimestampIdList().size());
		assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(simpleReport.getFirstTimestampId()));
		assertNull(detailedReport.getFirstSignatureId());
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getTimestampList().size());
		
		TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
		assertEquals(TimestampType.CONTENT_TIMESTAMP, timestampWrapper.getType());
		assertEquals(ArchiveTimestampType.CAdES_DETACHED, timestampWrapper.getArchiveTimestampType());
		
		assertEquals(2, timestampWrapper.getDigestMatchers().size());
		
		assertEquals(2, timestampWrapper.getTimestampedSignedDataIds().size());
		
		List<XmlSignerData> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertNotNull(originalSignerDocuments);
		assertEquals(2, originalSignerDocuments.size());
		
		int foundDocumentsCounter = 0;
		for (XmlDigestMatcher digestMatcher : timestampWrapper.getDigestMatchers()) {
			for (XmlSignerData signerData : originalSignerDocuments) {
				if (signerData.getReferencedName().equals(digestMatcher.getName())) {
					assertTrue(Arrays.equals(digestMatcher.getDigestValue(), signerData.getDigestAlgoAndValue().getDigestValue()));
					++foundDocumentsCounter;
				}
			}
		}
		assertEquals(2, foundDocumentsCounter);
		
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
		
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
		
		List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		
		boolean asicArchiveManifest = false;
		boolean originalFile = false;
		boolean manifestEntry = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if ("META-INF/ASiCArchiveManifest.xml".equals(digestMatcher.getName())) {
				asicArchiveManifest = true;
			}
			if ("original.bin".equals(digestMatcher.getName())) {
				originalFile = true;
			}
			if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				manifestEntry = true;
			}
		}
		assertTrue(asicArchiveManifest);
		assertTrue(originalFile);
		assertTrue(manifestEntry);
		
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
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
