package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureReferenceType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class CAdESSignatureWrapperTest extends PKIFactoryAccess {
	
	@Test
	public void signatureIdentifierTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/HU_POL/Signature-C-HU_POL-3.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertNotNull(signature.getDigestMatchers());
		assertEquals(1, signature.getDigestMatchers().size());
		assertNotNull(signature.getSignatureValue());
		
		ValidationReportType etsiValidationReport = report.getEtsiValidationReportJaxb();
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
		assertNotNull(signatureIdentifier);
		assertNotNull(signatureIdentifier.getDigestAlgAndValue());
		assertEquals(signature.getDigestMatchers().get(0).getDigestMethod(),
				DigestAlgorithm.forXML(signatureIdentifier.getDigestAlgAndValue().getDigestMethod().getAlgorithm()));
		assertTrue(Arrays.equals(signature.getDigestMatchers().get(0).getDigestValue(), signatureIdentifier.getDigestAlgAndValue().getDigestValue()));
		assertNotNull(signatureIdentifier.getSignatureValue());
		assertTrue(Arrays.equals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue()));
		
		XmlSignatureDigestReference signatureDigestReference = signature.getSignatureDigestReference();
		assertNotNull(signatureDigestReference);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cadesSignature = (CAdESSignature) signatures.get(0);
		CMSSignedData cmsSignedData = cadesSignature.getCmsSignedData();
		SignerInformationStore signerInfos = cmsSignedData.getSignerInfos();
		SignerInformation signerInformation = signerInfos.iterator().next();
		SignerInfo signerInfo = signerInformation.toASN1Structure();
		byte[] derEncoded = DSSASN1Utils.getDEREncoded(signerInfo);
		byte[] digest = DSSUtils.digest(signatureDigestReference.getDigestMethod(), derEncoded);
		
		String signatureReferenceDigestValue = Utils.toBase64(signatureDigestReference.getDigestValue());
		String signatureElementDigestValue = Utils.toBase64(digest);
		assertEquals(signatureReferenceDigestValue, signatureElementDigestValue);
		
		List<ValidationObjectType> validationObjects = etsiValidationReport.getSignatureValidationObjects().getValidationObject();
		int timestampCounter = 0;
		for (ValidationObjectType validationObject : validationObjects) {
			if (ObjectType.TIMESTAMP.equals(validationObject.getObjectType())) {
				POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
				List<SignatureReferenceType> signatureReferences = poeProvisioning.getSignatureReference();
				assertEquals(1, signatureReferences.size());
				SignatureReferenceType signatureReferenceType = signatureReferences.get(0);
				assertNotNull(signatureReferenceType.getDigestMethod());
				assertNotNull(signatureReferenceType.getDigestValue());
				assertNull(signatureReferenceType.getCanonicalizationMethod());
				assertNull(signatureReferenceType.getXAdESSignaturePtr());
				assertNull(signatureReferenceType.getPAdESFieldName());
				assertEquals(signatureReferenceDigestValue, Utils.toBase64(signatureReferenceType.getDigestValue()));
				timestampCounter++;
			}
		}
		assertEquals(2, timestampCounter);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
