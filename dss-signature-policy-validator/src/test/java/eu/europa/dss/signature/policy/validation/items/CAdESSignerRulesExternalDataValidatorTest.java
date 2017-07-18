package eu.europa.dss.signature.policy.validation.items;

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
