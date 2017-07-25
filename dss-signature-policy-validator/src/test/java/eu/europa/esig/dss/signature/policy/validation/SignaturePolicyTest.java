package eu.europa.esig.dss.signature.policy.validation;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.signature.policy.asn1.ASN1SignaturePolicy;

public class SignaturePolicyTest {
	
	@Test
	public void shouldReadFullPolicy() throws IOException {
		Path path = Paths.get(new File("src/test/resources/PA_PAdES_AD_RB_v1_0.der").toURI());
		byte[] policyContents = Files.readAllBytes(path);
		try (ASN1InputStream is = new ASN1InputStream(policyContents)) {
			ASN1Primitive asn1SP = is.readObject();
			ASN1SignaturePolicy.getInstance(asn1SP);
		}
	}
	
	@Test
	public void shouldReadValueFullPolicyAndMatchWrittenValue() throws IOException {
		Path path = Paths.get(new File("src/test/resources/PA_PAdES_AD_RB_v1_0.der").toURI());
		byte[] policyContents = Files.readAllBytes(path);
		try (ASN1InputStream is = new ASN1InputStream(policyContents)) {
			ASN1Primitive asn1SP = is.readObject();
			ASN1SignaturePolicy signaturePolicy = ASN1SignaturePolicy.getInstance(asn1SP);
			byte[] encoded = signaturePolicy.getEncoded();
			
			String original = Base64.toBase64String(policyContents);
			String generated = Base64.toBase64String(encoded);
			
			Assert.assertEquals(original, generated);
		}
	}
}
