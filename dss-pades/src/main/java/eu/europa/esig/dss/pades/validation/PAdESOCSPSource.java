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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.pdfbox.PdfDssDict;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 *
 *
 */

public class PAdESOCSPSource extends OfflineOCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESOCSPSource.class);

    private final CAdESSignature cadesSignature;
    private PdfDssDict dssCatalog;

    /**
     * The default constructor for PAdESOCSPSource.
     *
     * @param cadesSignature
     * @param dssCatalog
     */
    public PAdESOCSPSource(CAdESSignature cadesSignature, PdfDssDict dssCatalog) {
        this.cadesSignature = cadesSignature;
        this.dssCatalog = dssCatalog;
    }

    @Override
    public List<BasicOCSPResp> getContainedOCSPResponses() {
        List<BasicOCSPResp> result = new ArrayList<BasicOCSPResp>();

        // add OSCPs from embedded cadesSignature
        if (cadesSignature != null) {
            final List<BasicOCSPResp> containedOCSPResponses = cadesSignature.getOCSPSource().getContainedOCSPResponses();
            result.addAll(containedOCSPResponses);
        }

        if (dssCatalog != null) {
            // Add OSCPs from DSS catalog (LT level)

            final Set<BasicOCSPResp> ocspList = dssCatalog.getOcspList();
            for (final BasicOCSPResp basicOCSPResp : ocspList) {
                result.add(basicOCSPResp);
            }
        }
        return result;
    }
}
