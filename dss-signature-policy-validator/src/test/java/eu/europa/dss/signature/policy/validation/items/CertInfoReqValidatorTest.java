package eu.europa.dss.signature.policy.validation.items;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.dss.signature.policy.CertInfoReq;
import eu.europa.dss.signature.policy.validation.CertificateTestUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertInfoReqValidatorTest {
	@Test
	public void shouldValidateSignatureWithSignerOnlyRestrictionWithFullPathCertificates() throws Exception {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		
		CertInfoReqValidator validator = new CertInfoReqValidator(CertInfoReq.signerOnly, sig, null);
		Assert.assertTrue("signerOnly valid", validator.validate());
	}
	
	@Test
	public void shouldValidateSignatureWithNoneRestrictionWithSignerCertificate() throws Exception {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		
		CertInfoReqValidator validator = new CertInfoReqValidator(CertInfoReq.none, sig, null);
		Assert.assertTrue("none invalid", validator.validate());
	}
	
	@Test
	public void shouldNotValidateSignatureWithFullPathRestrictionWithNullCertificationPath() throws Exception {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		
		CertInfoReqValidator validator = new CertInfoReqValidator(CertInfoReq.fullPath, sig, null);
		Assert.assertFalse("fullPath invalid", validator.validate());
	}
	
	@Test
	public void shouldNotValidateSignatureWithFullPathRestrictionWithFullCertificationPath() throws Exception {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/cades/CAdES-A/Sample_Set_1/Signature-C-A-ATSv2-1.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		Set<CertificateToken> fullPath = new LinkedHashSet<>();
		sig.getCertificates();
		CertificateToken cert = CertificateTestUtils.loadIssuers(sig.getSigningCertificateToken(), sig.getCertPool());
		while (!cert.isSelfSigned()) {
			fullPath.add(cert);
			if (!cert.isSelfSigned()) {
				cert = cert.getIssuerToken();
			}
		}
		
		CertInfoReqValidator validator = new CertInfoReqValidator(CertInfoReq.fullPath, sig, fullPath);
		Assert.assertTrue("fullPath valid", validator.validate());
	}

}
