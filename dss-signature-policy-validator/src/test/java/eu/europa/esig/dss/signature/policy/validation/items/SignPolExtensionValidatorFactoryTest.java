package eu.europa.esig.dss.signature.policy.validation.items;

import java.io.IOException;
import java.util.Collections;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.signature.policy.PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.SignPolExtensions;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.asn1.ASN1PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.asn1.ASN1PBADPdfEntry;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class SignPolExtensionValidatorFactoryTest {

	@Test
	public void shouldValidateListWhenNoExtensionIsRequired() {
		SignPolExtensions spe = Mockito.mock(SignPolExtensions.class);
		AdvancedSignature as = Mockito.mock(AdvancedSignature.class);
		
		ItemValidator validator = SignPolExtensionValidatorFactory.createValidator(as, spe);
		Assert.assertTrue(validator.validate());
	}

	@Test
	public void shouldNotValidateListWhenUnkownExtensionIsRequired() {
		SignPolExtn signPolExtn = Mockito.mock(SignPolExtn.class);
		Mockito.doReturn("0.0.0.0.0.0.0").when(signPolExtn).getExtnID();
		
		SignPolExtensions spe = Mockito.mock(SignPolExtensions.class);
		Mockito.doReturn(Collections.singletonList(signPolExtn)).when(spe).getSignPolExtensions();
		AdvancedSignature as = Mockito.mock(AdvancedSignature.class);
		
		ItemValidator validator = SignPolExtensionValidatorFactory.createValidator(as, spe);
		Assert.assertFalse(validator.validate());
	}

	@Test
	public void shouldValidateListWhenExtensionIsRequiredAndEmpty() throws IOException {
		SignPolExtn signPolExtn = Mockito.mock(SignPolExtn.class);
		Mockito.doReturn(PBADMandatedPdfSigDicEntries.OID).when(signPolExtn).getExtnID();
		Mockito.doReturn(new ASN1PBADMandatedPdfSigDicEntries().toASN1Primitive().getEncoded()).when(signPolExtn).getExtnValue();
		
		SignPolExtensions spe = Mockito.mock(SignPolExtensions.class);
		Mockito.doReturn(Collections.singletonList(signPolExtn)).when(spe).getSignPolExtensions();
		PdfSignatureInfo si = Mockito.mock(PdfSignatureInfo.class);
		PAdESSignature as = Mockito.mock(PAdESSignature.class);
		Mockito.doReturn(si).when(as).getPdfSignatureInfo();
		
		ItemValidator validator = SignPolExtensionValidatorFactory.createValidator(as, spe);
		Assert.assertTrue(validator.validate());
	}

	@Test
	public void shouldValidateListWhenExtensionIsRequiredByType() throws IOException {
		SignPolExtn signPolExtn = Mockito.mock(SignPolExtn.class);
		Mockito.doReturn(PBADMandatedPdfSigDicEntries.OID).when(signPolExtn).getExtnID();
		Mockito.doReturn(new ASN1PBADMandatedPdfSigDicEntries(new ASN1PBADPdfEntry("Test")).toASN1Primitive().getEncoded()).when(signPolExtn).getExtnValue();
		
		SignPolExtensions spe = Mockito.mock(SignPolExtensions.class);
		Mockito.doReturn(Collections.singletonList(signPolExtn)).when(spe).getSignPolExtensions();
		PdfDict d = Mockito.mock(PdfDict.class);
		Mockito.doReturn(true).when(d).hasAName(Mockito.eq("Test"));
		PdfSignatureInfo si = Mockito.mock(PdfSignatureInfo.class);
		Mockito.doReturn(d).when(si).getSignatureDictionary();
		PAdESSignature as = Mockito.mock(PAdESSignature.class);
		Mockito.doReturn(si).when(as).getPdfSignatureInfo();
		
		ItemValidator validator = SignPolExtensionValidatorFactory.createValidator(as, spe);
		Assert.assertTrue(validator.validate());
	}

	@Test
	public void shouldValidateListWhenExtensionIsRequiredByTypeAndValue() throws IOException {
		SignPolExtn signPolExtn = Mockito.mock(SignPolExtn.class);
		Mockito.doReturn(PBADMandatedPdfSigDicEntries.OID).when(signPolExtn).getExtnID();
		Mockito.doReturn(new ASN1PBADMandatedPdfSigDicEntries(new ASN1PBADPdfEntry("Test", "aa")).toASN1Primitive().getEncoded()).when(signPolExtn).getExtnValue();
		
		SignPolExtensions spe = Mockito.mock(SignPolExtensions.class);
		Mockito.doReturn(Collections.singletonList(signPolExtn)).when(spe).getSignPolExtensions();
		PdfDict d = Mockito.mock(PdfDict.class);
		Mockito.doReturn(true).when(d).hasANameWithValue(Mockito.eq("Test"), Mockito.eq("aa"));
		PdfSignatureInfo si = Mockito.mock(PdfSignatureInfo.class);
		Mockito.doReturn(d).when(si).getSignatureDictionary();
		PAdESSignature as = Mockito.mock(PAdESSignature.class);
		Mockito.doReturn(si).when(as).getPdfSignatureInfo();
		
		ItemValidator validator = SignPolExtensionValidatorFactory.createValidator(as, spe);
		Assert.assertTrue(validator.validate());
	}

	@Test
	public void shouldNotValidateListWhenExtensionIsRequiredByTypeAndValueWithDifferentValue() throws IOException {
		SignPolExtn signPolExtn = Mockito.mock(SignPolExtn.class);
		Mockito.doReturn(PBADMandatedPdfSigDicEntries.OID).when(signPolExtn).getExtnID();
		Mockito.doReturn(new ASN1PBADMandatedPdfSigDicEntries(new ASN1PBADPdfEntry("Test", "AA")).toASN1Primitive().getEncoded()).when(signPolExtn).getExtnValue();
		
		SignPolExtensions spe = Mockito.mock(SignPolExtensions.class);
		Mockito.doReturn(Collections.singletonList(signPolExtn)).when(spe).getSignPolExtensions();
		PdfDict d = Mockito.mock(PdfDict.class);
		Mockito.doReturn(true).when(d).hasANameWithValue(Mockito.eq("Test"), Mockito.eq("Test1"));
		PdfSignatureInfo si = Mockito.mock(PdfSignatureInfo.class);
		Mockito.doReturn(d).when(si).getSignatureDictionary();
		PAdESSignature as = Mockito.mock(PAdESSignature.class);
		Mockito.doReturn(si).when(as).getPdfSignatureInfo();
		
		ItemValidator validator = SignPolExtensionValidatorFactory.createValidator(as, spe);
		Assert.assertFalse(validator.validate());
	}

	@Test
	public void shouldNotValidateListWhenExtensionIsMissingRequiredEntry() throws IOException {
		SignPolExtn signPolExtn = Mockito.mock(SignPolExtn.class);
		Mockito.doReturn(PBADMandatedPdfSigDicEntries.OID).when(signPolExtn).getExtnID();
		Mockito.doReturn(new ASN1PBADMandatedPdfSigDicEntries(new ASN1PBADPdfEntry("Test")).toASN1Primitive().getEncoded()).when(signPolExtn).getExtnValue();
		
		SignPolExtensions spe = Mockito.mock(SignPolExtensions.class);
		Mockito.doReturn(Collections.singletonList(signPolExtn)).when(spe).getSignPolExtensions();
		PdfDict d = Mockito.mock(PdfDict.class);
		PdfSignatureInfo si = Mockito.mock(PdfSignatureInfo.class);
		Mockito.doReturn(d).when(si).getSignatureDictionary();
		PAdESSignature as = Mockito.mock(PAdESSignature.class);
		Mockito.doReturn(si).when(as).getPdfSignatureInfo();
		
		ItemValidator validator = SignPolExtensionValidatorFactory.createValidator(as, spe);
		Assert.assertFalse(validator.validate());
	}
}
