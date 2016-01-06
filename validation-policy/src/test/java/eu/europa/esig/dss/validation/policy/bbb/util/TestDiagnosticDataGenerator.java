package eu.europa.esig.dss.validation.policy.bbb.util;

import java.util.Date;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureProductionPlace;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidationType;
import eu.europa.esig.dss.validation.report.DiagnosticData;

public class TestDiagnosticDataGenerator {
	
	private static String DOCUMENT_NAME = "Test document";

	public static DiagnosticData generateSimpleDiagnosticData() throws Exception {
		return new DiagnosticData(generateBasicData());
	}
	
	public static DiagnosticData generateDiagnosticDataWithPolicy() throws Exception {
		TestDiagnosticData data = generateBasicData();
		
		XmlPolicy policy = new XmlPolicy();
		policy.setId("Policy Test");
		policy.setStatus(true);
		policy.setIdentified(true);
		
		data.getSignature().get(0).setPolicy(policy);
		return new DiagnosticData(data);
	}
	
	public static DiagnosticData generateDiagnosticDataWithNonIntactSignature() throws Exception {
		TestDiagnosticData data = generateBasicData();
		
		data.getSignature().get(0).getBasicSignature().setSignatureIntact(false);
		return new DiagnosticData(data);
	}
	
	public static DiagnosticData generateDiagnosticReferenceDataWithNonIntactSignature() throws Exception {
		TestDiagnosticData data = generateBasicData();
		
		data.getSignature().get(0).getBasicSignature().setReferenceDataIntact(false);
		return new DiagnosticData(data);
	}
	
	public static DiagnosticData generateDiagnosticReferenceDataWithNotFound() throws Exception {
		TestDiagnosticData data = generateBasicData();
		
		data.getSignature().get(0).getBasicSignature().setReferenceDataFound(false);
		return new DiagnosticData(data);
	}
	
	private static TestDiagnosticData generateBasicData() throws Exception {
		TestDiagnosticData data = new TestDiagnosticData();
		data.setDocumentName(DOCUMENT_NAME);
		
		data.setUsedCertificates(TestUsedXmlCertificateGenerator.generateUsedCertificates());
		
		XmlSignatureProductionPlace productionPlace = new XmlSignatureProductionPlace();
		productionPlace.setCity("Luxembourg");
		productionPlace.setCountryName("Luxembourg");
		productionPlace.setPostalCode("L-1630");
		
		XmlSignature signature = new XmlSignature();
		signature.setId("TestId");
		signature.setDateTime(new Date());
		signature.setSignatureProductionPlace(productionPlace);
		signature.setSigningCertificate(data.getUsedCertificates().getCertificate().get(0).getSigningCertificate());
		signature.setBasicSignature(generateBasicSignatureType());
		signature.setCertificateChain(data.getUsedCertificates().getCertificate().get(0).getCertificateChain());
		XmlStructuralValidationType structure = new XmlStructuralValidationType();
		structure.setValid(true);
		signature.setStructuralValidation(structure);
		data.addXmlSignature(signature);
		
		return data;
	}
	
	private static XmlBasicSignatureType generateBasicSignatureType() {
		XmlBasicSignatureType basicSignature = new XmlBasicSignatureType();
		basicSignature.setDigestAlgoUsedToSignThisToken("SHA1");
		basicSignature.setEncryptionAlgoUsedToSignThisToken("RSA");
		basicSignature.setKeyLengthUsedToSignThisToken("1024");
		basicSignature.setReferenceDataFound(true);
		basicSignature.setReferenceDataIntact(true);
		basicSignature.setSignatureIntact(true);
		basicSignature.setSignatureValid(true);
		return basicSignature;
	}
}
