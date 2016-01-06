package eu.europa.esig.dss.validation.policy.bbb.util;

import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlUsedCertificates;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;

public class TestUsedXmlCertificateGenerator {

	public static XmlUsedCertificates generateUsedCertificates() throws Exception {
		CertificateService certService = new CertificateService();
		MockPrivateKeyEntry entry = certService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);
		
		XmlCertificate cert = new XmlCertificate();
		cert.setId(entry.getCertificate().getDSSIdAsString());
		cert.setSelfSigned(entry.getCertificate().isSelfSigned());
		cert.setTrusted(entry.getCertificate().isTrusted());
		cert.setNotBefore(entry.getCertificate().getNotBefore()); 
		cert.setNotAfter(entry.getCertificate().getNotAfter());
		cert.setPublicKeyEncryptionAlgo(entry.getEncryptionAlgorithm().getName());
		cert.setPublicKeySize(entry.getPrivateKey().getEncoded().length);
		
		XmlSigningCertificateType certType = new XmlSigningCertificateType();
		certType.setIssuerSerialMatch(true);
		certType.setAttributePresent(true);
		certType.setDigestValueMatch(true);
		certType.setDigestValuePresent(true);
		certType.setId(cert.getId());
		
		cert.setSigningCertificate(certType);
		
		XmlChainCertificate chain = new XmlChainCertificate();
		chain.setId("id test");
		chain.setSource("source test");
		XmlCertificateChainType chainType = new XmlCertificateChainType();
		cert.setCertificateChain(chainType);
		
		TestXmlUsedCertificates result = new TestXmlUsedCertificates();
		result.addXmlCertificates(cert);
		return result;
	}
}
