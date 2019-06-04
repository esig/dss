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

import static eu.europa.esig.dss.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.EncapsulatedTimestampTokenIdentifier;

/**
 * OCSPSource that retrieves information from a CAdESSignature.
 *
 *
 */
@SuppressWarnings("serial")
public class CAdESOCSPSource extends CMSOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESOCSPSource.class);
	
	/**
	 * Contains a link between timestamp ids and its embedded {@link CAdESTimeStampOCSPSource}s
	 */
	private Map<String, CAdESTimeStampOCSPSource> timeStampOCSPSourceMap;

	CAdESOCSPSource(CMSSignedData cms, AttributeTable unsignedAttributes) {
		super(cms, unsignedAttributes);
	}
	
	@Override
	protected void collectTimeStampData() {
		timeStampOCSPSourceMap = new HashMap<String, CAdESTimeStampOCSPSource>();
		findTimeStampCRLSources(id_aa_signatureTimeStampToken);
		findTimeStampCRLSources(id_aa_ets_certCRLTimestamp);
		findTimeStampCRLSources(id_aa_ets_escTimeStamp);
		findTimeStampCRLSources(id_aa_ets_archiveTimestampV2);
		findTimeStampCRLSources(id_aa_ets_archiveTimestampV3);
	}
	
	/**
	 * Finds OCPSSources for timestamps with a given {@code oid}
	 * @param unsignedAttributes {@link AttributeTable} to obtain timestamps from
	 * @param oid {@link ASN1ObjectIdentifier} to collect
	 */
	private void findTimeStampCRLSources(ASN1ObjectIdentifier oid) {
		List<TimeStampToken> timeStampTokens = DSSASN1Utils.findTimeStampTokens(unsignedAttributes, oid);
		for (final TimeStampToken timeStampToken : timeStampTokens) {
			try {
				CAdESTimeStampOCSPSource timeStampOCSPSource = new CAdESTimeStampOCSPSource(timeStampToken.toCMSSignedData(), timeStampToken.getUnsignedAttributes());
				addValuesFromInnerSource(timeStampOCSPSource);
				timeStampOCSPSourceMap.put(getTimestampId(timeStampToken), timeStampOCSPSource);
			} catch (IOException e) {
				LOG.warn("A found timestamp with oid [{}] is not correcly encoded! The source is not saved.", oid.toString());
			}
		}
	}
	
	/**
	 * Returns a {@link CAdESTimeStampOCSPSource} by its given {@code id}
	 * @param id {@link String}
	 * @return {@link CAdESTimeStampOCSPSource}
	 */
	public CAdESTimeStampOCSPSource getTimeStampOCSPSourceById(String id) {
		return timeStampOCSPSourceMap.get(id);
	}
	
	private String getTimestampId(TimeStampToken timeStampToken) throws IOException {
		return new EncapsulatedTimestampTokenIdentifier(timeStampToken.getEncoded()).asXmlId();
	}
	
}
