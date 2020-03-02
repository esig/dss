/**
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
 */
package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DSS818Test {

	private static final Logger LOGGER = LoggerFactory.getLogger(DSS818Test.class);

	@Test
	public void testCRY() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-818/Signature-P-DE_CRY-2 (HASH_FAILURE).pdf")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature advancedSignature : signatures) {
			PAdESSignature pades = (PAdESSignature) advancedSignature;
			CAdESSignature cades = pades.getCAdESSignature();

			byte[] encoded = cades.getCmsSignedData().getEncoded();

			checkSignedAttributesOrder(encoded);
		}
	}

	@Test
	public void testADO() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-818/Signature-P-IT_ADO-1 (HASH_FAILURE) (ECDSA).pdf")));

		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature advancedSignature : signatures) {
			PAdESSignature pades = (PAdESSignature) advancedSignature;
			CAdESSignature cades = pades.getCAdESSignature();

			byte[] encoded = cades.getCmsSignedData().getEncoded();

			checkSignedAttributesOrder(encoded);
		}
	}

	@Test
	public void testSK() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-818/Signature-P-SK-1 (HASH_FAILURE).pdf")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature advancedSignature : signatures) {
			PAdESSignature pades = (PAdESSignature) advancedSignature;
			CAdESSignature cades = pades.getCAdESSignature();

			byte[] encoded = cades.getCmsSignedData().getEncoded();

			checkSignedAttributesOrder(encoded);
		}
	}

	private void checkSignedAttributesOrder(byte[] encoded) throws Exception {
		ASN1InputStream asn1sInput = new ASN1InputStream(encoded);
		ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

		SignedData signedData = SignedData.getInstance(ASN1TaggedObject.getInstance(asn1Seq.getObjectAt(1)).getObject());

		ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
		LOGGER.info("SIGNER INFO ASN1 : " + signerInfosAsn1.toString());
		SignerInfo signedInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

		ASN1Set authenticatedAttributeSet = signedInfo.getAuthenticatedAttributes();
		LOGGER.info("AUTHENTICATED ATTR : " + authenticatedAttributeSet);

		boolean correctOrder = true;
		int previousSize = 0;
		for (int i = 0; i < authenticatedAttributeSet.size(); i++) {
			Attribute attribute = Attribute.getInstance(authenticatedAttributeSet.getObjectAt(i));
			ASN1ObjectIdentifier attrTypeOid = attribute.getAttrType();
			int size = attrTypeOid.getEncoded().length + attribute.getEncoded().length;
			LOGGER.info("ATTR " + i + " : size=" + size);

			if (size >= previousSize) {
				correctOrder = false;
			}

			previousSize = size;
		}
		assertFalse(correctOrder);
		Utils.closeQuietly(asn1sInput);
	}

}
