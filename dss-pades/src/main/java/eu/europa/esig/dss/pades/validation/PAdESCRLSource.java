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

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.CertificateList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;

/**
 * CRLSource that will retrieve the CRL from a PAdES Signature
 */
@SuppressWarnings("serial")
public class PAdESCRLSource extends PdfDssDictCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESCRLSource.class);

	private final String vriDictionaryName;

	public PAdESCRLSource(PdfDssDict dssDictionary, final String vriDictionaryName,
			AttributeTable signedAttributes) {
		Objects.requireNonNull(vriDictionaryName, "vriDictionaryName cannot be null!");
		this.vriDictionaryName = vriDictionaryName;
		extractDSSCRLs(dssDictionary);
		extractVRICRLs(dssDictionary);
		extractCRLArchivalValues(signedAttributes);
	}

	protected void extractCRLArchivalValues(AttributeTable signedAttributes) {
		if (signedAttributes != null) {
			final ASN1Encodable attValue = DSSASN1Utils.getAsn1Encodable(signedAttributes, OID.adbe_revocationInfoArchival);
			RevocationInfoArchival revValues = PAdESUtils.getRevocationInfoArchivals(attValue);
			if (revValues != null) {
				for (final CertificateList revValue : revValues.getCrlVals()) {
					try {
						addBinary(CRLUtils.buildCRLBinary(revValue.getEncoded()),
								RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
					} catch (Exception e) {
						LOG.warn("Could not convert CertificateList to CRLBinary : {}", e.getMessage());
					}
				}
			}
		}
	}

	@Override
	protected void extractVRICRLs(PdfVRIDict vriDictionary) {
		if (vriDictionary != null && vriDictionaryName.equals(vriDictionary.getName())) {
			super.extractVRICRLs(vriDictionary);
		}
	}

}
