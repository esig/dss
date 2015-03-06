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
package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;
import java.security.cert.X509CRL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSPDFUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

public class PdfDssDict {

    private static final Logger LOG = LoggerFactory.getLogger(PdfDssDict.class);

    private Set<X509CRL> crlList = new HashSet<X509CRL>();

    private Set<BasicOCSPResp> ocspList = new HashSet<BasicOCSPResp>();

    private Set<CertificateToken> certList = new HashSet<CertificateToken>();


    public static PdfDssDict build(PdfDict documentDict) throws IOException {
        if (documentDict != null) {

            final PdfDict dssCatalog = documentDict.getAsDict("DSS");
            if (dssCatalog != null) {
                return new PdfDssDict(dssCatalog);
            }
        }
        return null;
    }

    private PdfDssDict(PdfDict dssCatalog) throws IOException {
	    try {
		    readCerts(dssCatalog);
	    } catch (Exception e) {
		    LOG.debug(e.getMessage(), e);
	    }
        try {
            readCrl(dssCatalog);
        } catch (Exception e) {
            LOG.debug(e.getMessage(), e);
        }
        try {
            readOcsp(dssCatalog);
        } catch (Exception e) {
            LOG.debug(e.getMessage(), e);
        }
    }

    private void readCerts(PdfDict dssCatalog) throws IOException {
        final PdfArray certsArray = dssCatalog.getAsArray("Certs");
        if (certsArray != null) {

            LOG.debug("There is {} in this certsArray", certsArray.size());
            for (int ii = 0; ii < certsArray.size(); ii++) {

                final byte[] stream = certsArray.getBytes(ii);
                final CertificateToken cert = DSSUtils.loadCertificate(stream);
                certList.add(cert);
            }
        }
    }

    private void readOcsp(PdfDict dssCatalog) throws IOException {
        // Add OSCPs from DSS catalog (LT level)
        PdfArray ocspArray = dssCatalog.getAsArray("OCSPs");
        if (ocspArray != null) {
            LOG.debug("Found oscpArray of size {}", ocspArray.size());

            for (int ii = 0; ii < ocspArray.size(); ii++) {
                final byte[] stream = ocspArray.getBytes(ii);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("OSCP {} data = {}", ii, Hex.encodeHexString(stream));
                }
                final OCSPResp ocspResp = new OCSPResp(stream);
                final BasicOCSPResp responseObject;
                try {
                    responseObject = (BasicOCSPResp) ocspResp.getResponseObject();
                    ocspList.add(responseObject);
                } catch (OCSPException e) {
                    LOG.error("Error decoding ocspResp " + ocspResp, e);
                }
            }
        } else {
            LOG.debug("oscpArray is null");
        }

    }

    private void readCrl(PdfDict dssCatalog) {
        final PdfArray crlArray = dssCatalog.getAsArray("CRLs");
        if (crlArray != null) {

            for (int ii = 0; ii < crlArray.size(); ii++) {

                final byte[] bytes = DSSPDFUtils.getBytes(crlArray, ii);
                final X509CRL x509CRL = DSSUtils.loadCRL(bytes);
                crlList.add(x509CRL);
            }
        }
    }

    public Set<X509CRL> getCrlList() {
        return Collections.unmodifiableSet(crlList);
    }

    public Set<BasicOCSPResp> getOcspList() {
        return Collections.unmodifiableSet(ocspList);
    }

    public Set<CertificateToken> getCertList() {
        return Collections.unmodifiableSet(certList);
    }
}
