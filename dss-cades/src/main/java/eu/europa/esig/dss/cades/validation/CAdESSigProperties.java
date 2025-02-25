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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.validation.SignatureProperties;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a list of {@code CAdESAttribute}s
 */
public abstract class CAdESSigProperties implements SignatureProperties<CAdESAttribute> {

	private static final long serialVersionUID = -1730805576179343914L;

	/** The CMS attribute table set */
	private final ASN1Set asn1Set;

	/**
	 * The default constructor
	 *
	 * @param attributeTable {@link AttributeTable}
	 * @deprecated since DSS 6.0.1. Please use {@code new CAdESSigProperties(ASN1Set asn1Set)} instead
	 */
	@Deprecated
	CAdESSigProperties(AttributeTable attributeTable) {
		this.asn1Set = toASN1Set(attributeTable);
	}

	private static ASN1Set toASN1Set(AttributeTable attributeTable) {
		// TODO : method to ease migration. To be removed.
		if (attributeTable == null) {
			return null;
		}
		return new DERSet(attributeTable.toASN1EncodableVector());
	}

	/**
	 * The default constructor
	 *
	 * @param asn1Set {@link ASN1Set}
	 */
	CAdESSigProperties(final ASN1Set asn1Set) {
		this.asn1Set = asn1Set;
	}

	@Override
	public boolean isExist() {
		return asn1Set != null;
	}

	@Override
	public List<CAdESAttribute> getAttributes() {
		List<CAdESAttribute> attributes = new ArrayList<>();
		if (isExist()) {
			for (int ii = 0; ii < asn1Set.size(); ii++) {
				Attribute attribute = Attribute.getInstance(asn1Set.getObjectAt(ii));
				attributes.add(new CAdESAttribute(attribute, ii));
			}
		}
		return attributes;
	}

}
