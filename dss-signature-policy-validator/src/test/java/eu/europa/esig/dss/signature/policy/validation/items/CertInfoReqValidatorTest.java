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
package eu.europa.esig.dss.signature.policy.validation.items;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.policy.CertInfoReq;
import eu.europa.esig.dss.signature.policy.validation.CertificateTestUtils;
import eu.europa.esig.dss.signature.policy.validation.items.CertInfoReqValidator;
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
		while (cert != null) {
			fullPath.add(cert);
			cert = cert.getIssuerToken();
		}
		
		CertInfoReqValidator validator = new CertInfoReqValidator(CertInfoReq.fullPath, sig, fullPath);
		Assert.assertTrue("fullPath valid", validator.validate());
	}

}
