package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESCRLSource;
import eu.europa.esig.dss.pades.validation.PAdESCertificateSource;
import eu.europa.esig.dss.pades.validation.PAdESOCSPSource;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.x509.CertificateToken;

public class PAdESNoDuplicateValidationDataTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws IOException {
		
		DSSDocument toBeSigned = new InMemoryDocument(PAdESDoubleSignature.class.getResourceAsStream("/sample.pdf"));

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		Collection<Long> crlKeys = getCRLKeys(validator);
		Collection<Long> ocspKeys = getOCSPKeys(validator);
		Collection<Long> certKeys = getCertKeys(validator);
		
		checkValidationData(signedDocument, crlKeys, ocspKeys, certKeys);
		
		DSSDocument extendedDocument = service.extendDocument(signedDocument, params);
		checkValidationData(extendedDocument, crlKeys, ocspKeys, certKeys);
		
		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		checkValidationData(doubleSignedDocument, crlKeys, ocspKeys, certKeys);
		
		DSSDocument doubleSignedExtendedDocument = service.extendDocument(signedDocument, params);
		checkValidationData(doubleSignedExtendedDocument, crlKeys, ocspKeys, certKeys);
		
		// doubleSignedExtendedDocument.save("target/doubleSigned.pdf");
		
	}
	
	private Collection<Long> getCRLKeys(SignedDocumentValidator validator) {
		Collection<Long> crls = new ArrayList<Long>();
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESCRLSource crlSource = (PAdESCRLSource) signature.getCRLSource();
			crls.addAll(crlSource.getCrlMap().keySet());
		}
		return crls;
	}
	
	private Collection<Long> getOCSPKeys(SignedDocumentValidator validator) {
		Collection<Long> ocsps = new ArrayList<Long>();
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESOCSPSource ocspSource = (PAdESOCSPSource) signature.getOCSPSource();
			ocsps.addAll(ocspSource.getOcspMap().keySet());
		}
		return ocsps;
	}
	
	private Collection<Long> getCertKeys(SignedDocumentValidator validator) {
		Collection<Long> certs = new ArrayList<Long>();
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESCertificateSource certificateSource = (PAdESCertificateSource) signature.getCertificateSource();
			certs.addAll(certificateSource.getCertificateMap().keySet());
		}
		return certs;
	}
	
	private void checkValidationData(DSSDocument document, Collection<Long> crls, Collection<Long> ocsps, Collection<Long> certs) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESCRLSource crlSource = (PAdESCRLSource) signature.getCRLSource();
			Map<Long, byte[]> crlMap = crlSource.getCrlMap();
			assertEquals(1, crlMap.size());
			for (Long crl : crls) {
				assertNotNull(crlMap.get(crl));
			}
			
			PAdESOCSPSource ocspSource = (PAdESOCSPSource) signature.getOCSPSource();
			Map<Long, BasicOCSPResp> ocspMap = ocspSource.getOcspMap();
			assertEquals(1, ocspMap.size());
			for (Long ocsp : ocsps) {
				assertNotNull(ocspMap.get(ocsp));
			}
			
			PAdESCertificateSource certificateSource = (PAdESCertificateSource) signature.getCertificateSource();
			Map<Long, CertificateToken> certificateMap = certificateSource.getCertificateMap();
			for (Long cert : certs) {
				assertNotNull(certificateMap.get(cert));
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
