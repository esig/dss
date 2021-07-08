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

import eu.europa.esig.dss.cades.TimeStampTokenProductionComparator;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;

import java.util.Collections;
import java.util.List;

/**
 * Represents the CAdES Unsigned attributes
 */
public class CAdESUnsignedAttributes extends CAdESSigProperties {

	private static final long serialVersionUID = -2908905249481936152L;

	/**
	 * The default constructor
	 *
	 * @param attributeTable {@link AttributeTable} unsigned attributes table
	 */
	CAdESUnsignedAttributes(AttributeTable attributeTable) {
		super(attributeTable);
	}

	/**
	 * Builds the {@code CAdESUnsignedAttributes} from a {@code SignerInformation}
	 *
	 * @param signerInformation {@link SignerInformation} to build {@link CAdESUnsignedAttributes} from
	 * @return {@link CAdESUnsignedAttributes}
	 */
	public static CAdESUnsignedAttributes build(SignerInformation signerInformation) {
		return new CAdESUnsignedAttributes(signerInformation.getUnsignedAttributes());
	}
	
	@Override
	public List<CAdESAttribute> getAttributes() {
		List<CAdESAttribute> attributes = super.getAttributes();
		// Multiple timestamps need to be sorted in CAdES by their production date
		return sortTimestamps(attributes, DSSASN1Utils.getTimestampOids());
	}
	
	private List<CAdESAttribute> sortTimestamps(List<CAdESAttribute> attributes, List<ASN1ObjectIdentifier> timestampOids) {
		TimeStampTokenProductionComparator comparator = new TimeStampTokenProductionComparator();
		for (int ii = 0; ii < attributes.size() - 1; ii++) {
			for (int jj = 0; jj < attributes.size() - ii - 1; jj++) {
				CAdESAttribute cadesAttribute = attributes.get(jj);
				// if the element is a timestamp
				if (timestampOids.contains(cadesAttribute.getASN1Oid())) {
					CAdESAttribute nextCAdESAttribute = attributes.get(jj + 1);
					// swap if the next element is not a timestamp
					if (!timestampOids.contains(nextCAdESAttribute.getASN1Oid())) {
						Collections.swap(attributes, jj, jj + 1);
					} else {
						TimeStampToken current = cadesAttribute.toTimeStampToken();
						TimeStampToken next = nextCAdESAttribute.toTimeStampToken();
						// swap if the current element was generated after the following timestamp attribute
						if (current != null && next != null && (comparator.compare(current, next) > 0)) {
							Collections.swap(attributes, jj, jj + 1);
						}

					}
				}
			}
		}
		return attributes;
	}

}