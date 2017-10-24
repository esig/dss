/*******************************************************************************
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 ******************************************************************************/
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
