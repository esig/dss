/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite.dss818;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractDSS818Test extends AbstractPAdESTestValidation {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractDSS818Test.class);
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		for (AdvancedSignature advancedSignature : signatures) {
			try {
				PAdESSignature pades = (PAdESSignature) advancedSignature;
	
				byte[] encoded = pades.getCmsSignedData().getEncoded();
	
				checkSignedAttributesOrder(encoded);
			} catch (Exception e) {
				fail(e);
			}
		}
	}

	private void checkSignedAttributesOrder(byte[] encoded) throws Exception {
		try (ASN1InputStream asn1sInput = new ASN1InputStream(encoded)) {
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();
	
			SignedData signedData = SignedData.getInstance(ASN1TaggedObject.getInstance(asn1Seq.getObjectAt(1)).getBaseObject());
	
			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			LOG.debug("SIGNER INFO ASN1 : " + signerInfosAsn1.toString());
			SignerInfo signedInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));
	
			ASN1Set authenticatedAttributeSet = signedInfo.getAuthenticatedAttributes();
			LOG.debug("AUTHENTICATED ATTR : " + authenticatedAttributeSet);
	
			boolean correctOrder = true;
			int previousSize = 0;
			for (int i = 0; i < authenticatedAttributeSet.size(); i++) {
				Attribute attribute = Attribute.getInstance(authenticatedAttributeSet.getObjectAt(i));
				ASN1ObjectIdentifier attrTypeOid = attribute.getAttrType();
				int size = attrTypeOid.getEncoded().length + attribute.getEncoded().length;
				LOG.debug("ATTR " + i + " : size=" + size);
	
				if (size >= previousSize) {
					correctOrder = false;
				}
	
				previousSize = size;
			}
			assertFalse(correctOrder);
		}
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
