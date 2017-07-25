package eu.europa.esig.dss.signature.policy.validation.items;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.policy.validation.items.CmsSignatureAttributesValidator;

public class CmsSignatureAttributesValidatorTest {

	@Test
	public void shouldValidateCmsWithAllValidAttributes() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		CmsSignatureAttributesValidator validator = new CmsSignatureAttributesValidator(Arrays.asList(
				PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId(),
				PKCSObjectIdentifiers.pkcs_9_at_contentType.getId()), CMSUtils.getSignedAttributes(sig.getSignerInformation()));
		Assert.assertTrue(validator.validate());
	}

	@Test
	public void shouldNotValidateCmsWithMissingAttribute() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		CmsSignatureAttributesValidator validator = new CmsSignatureAttributesValidator(Arrays.asList(
				PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId(),
				PKCSObjectIdentifiers.pkcs_9_at_contentType.getId(),
				PKCSObjectIdentifiers.pkcs_9_at_counterSignature.getId()), CMSUtils.getSignedAttributes(sig.getSignerInformation()));
		Assert.assertFalse(validator.validate());
	}

	@Test
	public void shouldNotValidateCmsWithNullRequiredAttributes() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		CmsSignatureAttributesValidator validator = new CmsSignatureAttributesValidator(null, CMSUtils.getSignedAttributes(sig.getSignerInformation()));
		Assert.assertTrue(validator.validate());
	}

	@Test
	public void shouldNotValidateCmsWithEmptyRequiredAttributes() throws CMSException, IOException {
		Path documentPath = Paths.get(new File("../dss-cades/src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m").toURI());
		byte[] contents = Files.readAllBytes(documentPath);
		CAdESSignature sig = new CAdESSignature(contents);
		CmsSignatureAttributesValidator validator = new CmsSignatureAttributesValidator(Collections.EMPTY_LIST, CMSUtils.getSignedAttributes(sig.getSignerInformation()));
		Assert.assertTrue(validator.validate());
	}
}
