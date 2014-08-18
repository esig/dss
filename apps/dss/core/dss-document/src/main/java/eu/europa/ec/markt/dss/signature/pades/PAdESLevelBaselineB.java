/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.pades;

import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.cades.CAdESLevelBaselineB;

/**
 * EPES profile for PAdES signature
 *
 * @version $Revision: 2723 $ - $Date: 2013-10-11 11:51:11 +0200 (Fri, 11 Oct 2013) $
 */

class PAdESLevelBaselineB {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBaselineB.class);

	AttributeTable getSignedAttributes(Map params, CAdESLevelBaselineB cadesProfile, SignatureParameters parameters, byte[] messageDigest) {

		AttributeTable signedAttributes = cadesProfile.getSignedAttributes(parameters);

		if (signedAttributes.get(CMSAttributes.contentType) == null) {

			DERObjectIdentifier contentType = (DERObjectIdentifier) params.get(CMSAttributeTableGenerator.CONTENT_TYPE);

			// contentType will be null if we're trying to generate a counter signature.
			if (contentType != null) {
				signedAttributes = signedAttributes.add(CMSAttributes.contentType, contentType);
			}
		}

		if (signedAttributes.get(CMSAttributes.messageDigest) == null) {
			// byte[] messageDigest = (byte[]) params.get(CMSAttributeTableGenerator.DIGEST);
			signedAttributes = signedAttributes.add(CMSAttributes.messageDigest, new DEROctetString(messageDigest));
		}

		return signedAttributes;
	}

	AttributeTable getUnsignedAttributes() {
		return new AttributeTable(new Hashtable());
	}

}
