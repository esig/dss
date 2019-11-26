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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;

import eu.europa.esig.dss.validation.SignatureProperties;

public abstract class CAdESSigProperties implements SignatureProperties<CAdESAttribute> {
	
	private final AttributeTable attributeTable;
	
	CAdESSigProperties(AttributeTable attributeTable) {
		this.attributeTable = attributeTable;
	}

	@Override
	public boolean isExist() {
		return attributeTable != null;
	}

	@Override
	public List<CAdESAttribute> getAttributes() {
		List<CAdESAttribute> attributes = new ArrayList<CAdESAttribute>();
		if (isExist()) {
			ASN1EncodableVector asn1EncodableVector = attributeTable.toASN1EncodableVector();
			for (int ii = 0; ii < asn1EncodableVector.size(); ii++) {
				Attribute attribute = (Attribute) asn1EncodableVector.get(ii);
				attributes.add(new CAdESAttribute(attribute));
			}
		}
		return attributes;
	}

}
