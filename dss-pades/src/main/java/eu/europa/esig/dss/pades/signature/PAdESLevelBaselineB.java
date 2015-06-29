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
package eu.europa.esig.dss.pades.signature;

import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerator;

import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineB;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;

/**
 * PAdES Baseline B signature
 *
 */
class PAdESLevelBaselineB {

	AttributeTable getSignedAttributes(Map params, CAdESLevelBaselineB cadesProfile, PAdESSignatureParameters parameters, byte[] messageDigest) {

		AttributeTable signedAttributes = cadesProfile.getSignedAttributes(parameters);

		if (signedAttributes.get(CMSAttributes.contentType) == null) {
			ASN1ObjectIdentifier contentType = (ASN1ObjectIdentifier) params.get(CMSAttributeTableGenerator.CONTENT_TYPE);
			// contentType will be null if we're trying to generate a counter signature.
			if (contentType != null) {
				signedAttributes = signedAttributes.add(CMSAttributes.contentType, contentType);
			}
		}

		if (signedAttributes.get(CMSAttributes.messageDigest) == null) {
			signedAttributes = signedAttributes.add(CMSAttributes.messageDigest, new DEROctetString(messageDigest));
		}

		return signedAttributes;
	}

	AttributeTable getUnsignedAttributes() {
		return new AttributeTable(new Hashtable());
	}

}