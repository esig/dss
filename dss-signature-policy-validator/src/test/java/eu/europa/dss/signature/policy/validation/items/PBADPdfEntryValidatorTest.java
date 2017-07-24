package eu.europa.dss.signature.policy.validation.items;

import java.io.File;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.dss.signature.policy.asn1.ASN1PBADMandatedPdfSigDicEntries;
import eu.europa.dss.signature.policy.asn1.ASN1PBADPdfEntry;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class PBADPdfEntryValidatorTest {

	@Test
	public void shouldNotValidateWhenDictionaryEntriesDifferentValue() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("../dss-pades/src/test/resources/validation/dss-818/Signature-P-IT_ADO-1 (HASH_FAILURE) (ECDSA).pdf")));

		List<AdvancedSignature> signatures = validator.getSignatures();
		ASN1PBADMandatedPdfSigDicEntries mandatedEntries = new ASN1PBADMandatedPdfSigDicEntries(
				new ASN1PBADPdfEntry("Type", "Sig"), new ASN1PBADPdfEntry("Filter", "PBAD_PAdES"), new ASN1PBADPdfEntry("SubFilter", "PBAD.PAdES"), new ASN1PBADPdfEntry("Contents"), new ASN1PBADPdfEntry("ByteRange")
				);
		PBADPdfEntryValidator pbadPdfEntryValidator = new PBADPdfEntryValidator(signatures.get(0), mandatedEntries);
		Assert.assertFalse("Not valid entries", pbadPdfEntryValidator.validate());
		Assert.assertEquals(2, pbadPdfEntryValidator.getInvalidEntries().size());
		Assert.assertTrue(pbadPdfEntryValidator.getInvalidEntries().contains("Filter=Adobe.PPKLite"));
		Assert.assertTrue(pbadPdfEntryValidator.getInvalidEntries().contains("SubFilter=ETSI.CAdES.detached"));
	}

	@Test
	public void shouldValidateWhenDictionaryEntriesFound() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/AD-RT-bry-ts-oid-uri.pdf")));

		List<AdvancedSignature> signatures = validator.getSignatures();
		ASN1PBADMandatedPdfSigDicEntries mandatedEntries = new ASN1PBADMandatedPdfSigDicEntries(
				new ASN1PBADPdfEntry("Type", "Sig"), new ASN1PBADPdfEntry("Filter", "PBAD_PAdES"), new ASN1PBADPdfEntry("SubFilter", "PBAD.PAdES"), new ASN1PBADPdfEntry("Contents"), new ASN1PBADPdfEntry("ByteRange")
				);
		PBADPdfEntryValidator pbadPdfEntryValidator = new PBADPdfEntryValidator(signatures.get(0), mandatedEntries);
		boolean validate = pbadPdfEntryValidator.validate();
		Assert.assertTrue("Not expecting invalid: " + pbadPdfEntryValidator.getInvalidEntries(), validate);
	}
}
