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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.policy.validation.items.CAdESSignerRulesExternalDataValidator;

public class CAdESSignerRulesExternalDataValidatorTest {
	@Test
	public void shouldValidateDocumentWithoutRestrictions() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		CAdESSignerRulesExternalDataValidator validator = new CAdESSignerRulesExternalDataValidator(sig, null);
		Assert.assertTrue(validator.validate());
	}
	
	@Test
	public void shouldValidateDocumentWithoutExternalContentWithoutRestrictions() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		
		// Remove contents of signature making a detached signature
		CMSSignedData cms = new CMSSignedData(contents);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		gen.addCertificates(cms.getCertificates());
		gen.addSigners(cms.getSignerInfos());
		cms = gen.generate(cms.getSignedContent(), false);
		
		CAdESSignature sig = new CAdESSignature(cms.getEncoded());
		CAdESSignerRulesExternalDataValidator validator = new CAdESSignerRulesExternalDataValidator(sig, null);
		Assert.assertTrue(validator.validate());
	}
	
	@Test
	public void shouldValidateAttachedDocumentWhenNotExternalData() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		CAdESSignerRulesExternalDataValidator validator = new CAdESSignerRulesExternalDataValidator(sig, false);
		Assert.assertTrue(validator.validate());
	}
	
	@Test
	public void shouldValidateDocumentDettachedWhenExternalContent() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		
		// Remove contents of signature making a detached signature
		CMSSignedData cms = new CMSSignedData(contents);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		gen.addCertificates(cms.getCertificates());
		gen.addSigners(cms.getSignerInfos());
		cms = gen.generate(cms.getSignedContent(), false);
		
		CAdESSignature sig = new CAdESSignature(cms.getEncoded());
		CAdESSignerRulesExternalDataValidator validator = new CAdESSignerRulesExternalDataValidator(sig, true);
		Assert.assertTrue(validator.validate());
	}	
	
}
