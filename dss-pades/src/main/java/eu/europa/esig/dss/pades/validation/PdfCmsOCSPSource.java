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
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a source of OCSP tokens extracted from a PDF's CMS
 *
 */
public class PdfCmsOCSPSource extends OfflineOCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PdfCmsOCSPSource.class);

    /**
     * The default constructor
     *
     * @param signedAttributes {@link AttributeTable}
     */
    public PdfCmsOCSPSource(AttributeTable signedAttributes) {
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

}
