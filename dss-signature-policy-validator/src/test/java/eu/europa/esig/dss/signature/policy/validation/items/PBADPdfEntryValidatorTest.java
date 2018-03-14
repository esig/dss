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
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.policy.PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.asn1.ASN1PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.asn1.ASN1PBADPdfEntry;
import eu.europa.esig.dss.signature.policy.validation.items.PBADPdfEntryValidator;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class PBADPdfEntryValidatorTest {

	@Test
	public void shouldNotValidateWhenDictionaryEntriesDifferentValue() throws IOException {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("../dss-pades/src/test/resources/validation/dss-818/Signature-P-IT_ADO-1 (HASH_FAILURE) (ECDSA).pdf")));

		List<AdvancedSignature> signatures = validator.getSignatures();
		PBADMandatedPdfSigDicEntries mandatedEntries = new ASN1PBADMandatedPdfSigDicEntries(
				new ASN1PBADPdfEntry("Type", "Sig"), new ASN1PBADPdfEntry("Filter", "PBAD_PAdES"), new ASN1PBADPdfEntry("SubFilter", "PBAD.PAdES"), new ASN1PBADPdfEntry("Contents"), new ASN1PBADPdfEntry("ByteRange")
				);
		PBADPdfEntryValidator pbadPdfEntryValidator = new PBADPdfEntryValidator(signatures.get(0), mandatedEntries);
		Assert.assertFalse("Not valid entries", pbadPdfEntryValidator.validate());
		Assert.assertEquals(2, pbadPdfEntryValidator.getInvalidEntries().size());
		Assert.assertTrue(pbadPdfEntryValidator.getInvalidEntries().contains("Filter=Adobe.PPKLite"));
		Assert.assertTrue(pbadPdfEntryValidator.getInvalidEntries().contains("SubFilter=ETSI.CAdES.detached"));
	}

	@Test
	public void shouldValidateWhenDictionaryEntriesFound() throws IOException {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/AD-RT-bry-ts-oid-uri.pdf")));

		List<AdvancedSignature> signatures = validator.getSignatures();
		PBADMandatedPdfSigDicEntries mandatedEntries = new ASN1PBADMandatedPdfSigDicEntries(
				new ASN1PBADPdfEntry("Type", "Sig"), new ASN1PBADPdfEntry("Filter", "PBAD_PAdES"), new ASN1PBADPdfEntry("SubFilter", "PBAD.PAdES"), new ASN1PBADPdfEntry("Contents"), new ASN1PBADPdfEntry("ByteRange")
				);
		PBADPdfEntryValidator pbadPdfEntryValidator = new PBADPdfEntryValidator(signatures.get(0), mandatedEntries);
		boolean validate = pbadPdfEntryValidator.validate();
		Assert.assertTrue("Not expecting invalid: " + pbadPdfEntryValidator.getInvalidEntries(), validate);
	}
}
