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

import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.validation.timestamp.TimeStampTokenProductionComparator;

public class CAdESUnsignedAttributes extends CAdESSigProperties {
	
	private static List<ASN1ObjectIdentifier> timestampOids;
	
	static {
		timestampOids = new ArrayList<>();
		timestampOids.add(id_aa_ets_archiveTimestampV2);
		timestampOids.add(id_aa_ets_archiveTimestampV3);
		timestampOids.add(id_aa_ets_certCRLTimestamp);
		timestampOids.add(id_aa_ets_escTimeStamp);
		timestampOids.add(id_aa_signatureTimeStampToken);
	}

	CAdESUnsignedAttributes(AttributeTable attributeTable) {
		super(attributeTable);
	}
	
	public static CAdESUnsignedAttributes build(SignerInformation signerInformation) {
		return new CAdESUnsignedAttributes(signerInformation.getUnsignedAttributes());
	}
	
	@Override
	public List<CAdESAttribute> getAttributes() {
		// Multiple timestamps need to be sorted in CAdES by their production date
		return sortTimestamps(super.getAttributes());
	}
	
	private List<CAdESAttribute> sortTimestamps(List<CAdESAttribute> attributes) {
		// TODO: improve ?
		TimeStampTokenProductionComparator comparator = new TimeStampTokenProductionComparator();
		
		for (int ii = 0; ii < attributes.size() - 1; ii++) {
			for (int jj = 0; jj < attributes.size() - ii - 1; jj++) {
				CAdESAttribute cadesAttribute = attributes.get(jj);
				// if the first element is a timestamp
				if (timestampOids.contains(cadesAttribute.getASN1Oid())) {
					CAdESAttribute nextCAdESAttribute = attributes.get(jj+1);
					// swap if the next element is not a timestamp
					if (!timestampOids.contains(nextCAdESAttribute.getASN1Oid())) {
						Collections.swap(attributes, jj, jj+1);
					} 
					// swap if the current element was generated after the following timestamp attribute
					else if (comparator.compare(cadesAttribute.toTimeStampToken(), nextCAdESAttribute.toTimeStampToken()) > 0) {
						Collections.swap(attributes, jj, jj+1);
					}
				}
			}
		}
		return attributes;
	}

}