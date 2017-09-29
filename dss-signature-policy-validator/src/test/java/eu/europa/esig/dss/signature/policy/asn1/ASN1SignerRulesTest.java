package eu.europa.esig.dss.signature.policy.asn1;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.Test;

import eu.europa.esig.dss.signature.policy.CertInfoReq;
import eu.europa.esig.dss.signature.policy.CertRefReq;

public class ASN1SignerRulesTest {
	
	@Test
	public void testGetMandatedCertificateRef_ShouldReturnSignerOnlyWhenItsValueIsNull() throws Exception {
		Path path = Paths
				.get(new File("src/test/resources/no_mandatedCertificateRef_no_mandatedCertificateInfo.der").toURI());
		byte[] policyContents = Files.readAllBytes(path);
		try (ASN1InputStream is = new ASN1InputStream(policyContents)) {
			ASN1Primitive asn1SP = is.readObject();
			ASN1SignaturePolicy signaturePolicy = ASN1SignaturePolicy.getInstance(asn1SP);
			CertRefReq certRefReq = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules().getMandatedCertificateRef();
			assertNotNull(certRefReq);
			assertEquals(certRefReq, CertRefReq.signerOnly);
		}
	}

	@Test
	public void testGetMandatedCertificateRef() throws Exception {
		Path path = Paths.get(new File("src/test/resources/PA_with_mandatedCertificateRef.der").toURI());
		byte[] policyContents = Files.readAllBytes(path);
		try (ASN1InputStream is = new ASN1InputStream(policyContents)) {
			ASN1Primitive asn1SP = is.readObject();
			ASN1SignaturePolicy signaturePolicy = ASN1SignaturePolicy.getInstance(asn1SP);
			CertRefReq certRefReq = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules().getMandatedCertificateRef();
			assertNotNull(certRefReq);
			assertEquals(certRefReq, CertRefReq.fullPath);
		}
	}

	@Test
	public void testGetMandatedCertificateInfo_ShouldReturnNoneWhenItsValueIsNull() throws IOException {
		Path path = Paths
				.get(new File("src/test/resources/no_mandatedCertificateRef_no_mandatedCertificateInfo.der").toURI());
		byte[] policyContents = Files.readAllBytes(path);
		try (ASN1InputStream is = new ASN1InputStream(policyContents)) {
			ASN1Primitive asn1SP = is.readObject();
			ASN1SignaturePolicy signaturePolicy = ASN1SignaturePolicy.getInstance(asn1SP);
			CertInfoReq certInfoReq = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateInfo();
			assertNotNull(certInfoReq);
			assertEquals(certInfoReq, CertInfoReq.none);
		}
	}

	@Test
	public void testGetMandatedCertificateInfo() throws IOException {
		Path path = Paths.get(new File("src/test/resources/PA_with_mandatedCertificateRef.der").toURI());
		byte[] policyContents = Files.readAllBytes(path);
		try (ASN1InputStream is = new ASN1InputStream(policyContents)) {
			ASN1Primitive asn1SP = is.readObject();
			ASN1SignaturePolicy signaturePolicy = ASN1SignaturePolicy.getInstance(asn1SP);
			CertInfoReq certInfoReq = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateInfo();
			assertNotNull(certInfoReq);
			assertEquals(certInfoReq, CertInfoReq.signerOnly);
		}
	}
}
