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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CAdESWithContentTimestampTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		FileDocument fileDocument = new FileDocument("src/test/resources/validation/Signature-C-BES-4.p7m");
		
		try (InputStream is = fileDocument.openStream(); ASN1InputStream asn1sInput = new ASN1InputStream(is)) {
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

			ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Seq.getObjectAt(1));
			ASN1Object object = taggedObj.getBaseObject();
			SignedData signedData = SignedData.getInstance(object);

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			ASN1Sequence seqSignedInfo = ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0));

			SignerInfo signedInfo = SignerInfo.getInstance(seqSignedInfo);
			ASN1Set authenticatedAttributes = signedInfo.getAuthenticatedAttributes();

			boolean found = false;
			for (int i = 0; i < authenticatedAttributes.size(); i++) {
				ASN1Sequence authAttrSeq = ASN1Sequence.getInstance(authenticatedAttributes.getObjectAt(i));
				ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(authAttrSeq.getObjectAt(0));
				if (PKCSObjectIdentifiers.id_aa_ets_contentTimestamp.equals(attrOid)) {
					found = true;
				}
			}
			assertTrue(found);
		} catch (Exception e) {
			fail(e);
		}
		
		return fileDocument;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionNotEmpty(timestampIdList));

		boolean foundContentTimestamp = false;
		for (String timestampId : timestampIdList) {
			TimestampType timestampType = diagnosticData.getTimestampType(timestampId);
			if (TimestampType.CONTENT_TIMESTAMP.equals(timestampType)) {
				foundContentTimestamp = true;
			}
		}
		assertTrue(foundContentTimestamp);
	}

}
