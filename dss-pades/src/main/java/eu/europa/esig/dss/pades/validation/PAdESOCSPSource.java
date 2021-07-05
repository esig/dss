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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 *
 */
@SuppressWarnings("serial")
public class PAdESOCSPSource extends PdfDssDictOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESOCSPSource.class);

	/** The name of the corresponding VRI dictionary */
	private final String vriDictionaryName;

	/**
	 * The default constructor
	 *
	 * @param dssDictionary {@link PdfDssDict}
	 * @param vriDictionaryName {@link String} the corresponding VRI dictionary name to extract
	 * @param signedAttributes {@link AttributeTable}
	 */
	public PAdESOCSPSource(PdfDssDict dssDictionary, final String vriDictionaryName,
			AttributeTable signedAttributes) {
		Objects.requireNonNull(vriDictionaryName, "vriDictionaryName cannot be null!");
		this.vriDictionaryName = vriDictionaryName;
		extractDSSOCSPs(dssDictionary);
		extractVRIOCSPs(dssDictionary);
		extractOCSPArchivalValues(signedAttributes);
	}

	private void extractOCSPArchivalValues(AttributeTable signedAttributes) {
		if (signedAttributes != null) {
			final ASN1Encodable attValue = DSSASN1Utils.getAsn1Encodable(signedAttributes, OID.adbe_revocationInfoArchival);
			if (attValue != null) {
				RevocationInfoArchival revocationArchival = PAdESUtils.getRevocationInfoArchival(attValue);
				if (revocationArchival != null) {
					for (final OCSPResponse ocspResponse : revocationArchival.getOcspVals()) {
						try {
							BasicOCSPResp basicOCSPResponse = DSSASN1Utils.toBasicOCSPResp(ocspResponse);
							addBinary(OCSPResponseBinary.build(basicOCSPResponse),
									RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
						} catch (OCSPException e) {
							LOG.warn("Error while extracting OCSPResponse from Revocation Info Archivals (ADBE) : {}",
									e.getMessage());
						}
					}
				}
			}
		}
	}

	@Override
	protected void extractVRIOCSPs(PdfVRIDict vriDictionary) {
		if (vriDictionary != null && vriDictionaryName.equals(vriDictionary.getName())) {
			super.extractVRIOCSPs(vriDictionary);
		}
	}

}
