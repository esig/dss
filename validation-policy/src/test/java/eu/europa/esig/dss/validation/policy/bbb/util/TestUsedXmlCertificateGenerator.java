package eu.europa.esig.dss.validation.policy.bbb.util;

import java.util.Date;

import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationType;
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
		cert.setSelfSigned(true);
		cert.setTrusted(true);
		cert.setNotBefore(entry.getCertificate().getNotBefore());
		cert.setNotAfter(entry.getCertificate().getNotAfter());
		cert.setPublicKeyEncryptionAlgo(entry.getEncryptionAlgorithm().getName());
		cert.setPublicKeySize(DSSPKUtils.getPublicKeySize(entry.getCertificate().getPublicKey()));

		XmlSigningCertificateType certType = new XmlSigningCertificateType();
		certType.setIssuerSerialMatch(true);
		certType.setAttributePresent(true);
		certType.setDigestValueMatch(true);
		certType.setDigestValuePresent(true);
		certType.setId(cert.getId());
		certType.setSigned("X509Certificate");

		cert.setSigningCertificate(certType);

		XmlChainCertificate chain = new XmlChainCertificate();
		chain.setId(entry.getCertificate().getDSSIdAsString());
		chain.setSource("TRUSTED_STORE");
		XmlCertificateChainType chainType = new XmlCertificateChainType();
		chainType.getChainCertificate().add(chain);
		cert.setCertificateChain(chainType);

		XmlBasicSignatureType basicType = new XmlBasicSignatureType();
		basicType.setDigestAlgoUsedToSignThisToken("SHA1");
		basicType.setEncryptionAlgoUsedToSignThisToken("RSA");
		basicType.setKeyLengthUsedToSignThisToken("1024");
		basicType.setReferenceDataFound(true);
		basicType.setReferenceDataIntact(true);
		basicType.setSignatureIntact(true);
		basicType.setSignatureValid(true);
		cert.setBasicSignature(basicType);

		XmlRevocationType revocationType = new XmlRevocationType();
		revocationType.setBasicSignature(basicType);
		revocationType.setCertificateChain(chainType);
		revocationType.setProductionDate(new Date());
		revocationType.setSigningCertificate(certType);
		revocationType.setSource("OCSP_RESPONSE");
		revocationType.setRevocationDate(new Date());
		revocationType.setStatus(true);
		revocationType.setNextUpdate(new Date());
		// revocationType.setReason("certificateHold");

		cert.getRevocation().add(revocationType);

		TestXmlUsedCertificates result = new TestXmlUsedCertificates();
		result.addXmlCertificates(cert);
		return result;
	}
}
