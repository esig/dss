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
package eu.europa.esig.dss.x509;

import java.util.Date;

import eu.europa.esig.dss.DSSUtils;

public class CertificateTokenValidationExtraInfo extends TokenValidationExtraInfo {

    /**
     *
     */
    public void infoOCSPSourceIsNull() {

        validationInfo.add("The OCSP source is null!");
    }

    /**
     *
     */
    public void infoNoOCSPResponse(final String uri) {

        validationInfo.add("There is no OCSP response! (uri: " + uri + ")");
    }

    /**
     *
     */
    public void infoOCSPException(final Exception e) {

        validationInfo.add("An exception occurred during the OCSP retrieval process: " + e.getMessage());
    }

    /**
     *
     */
    public void infoCRLSourceIsNull() {

        validationInfo.add("The CRL source is null!");
    }

    /**
     *
     */
    public void infoNoCRLInfoFound(final String uri) {

        validationInfo.add("No CRL info found! (" + uri + ")");
    }

    /**
     *
     */
    public void infoCRLSignatureIsNotValid(final String message) {

        validationInfo.add("The CRL signature is not valid: " + message);
    }

    /**
     *
     */
    public void infoCRLIsNotValid() {

        validationInfo.add("The CRL is not valid!");
    }

    /**
     *
     */
    public void infoCRLException(final Exception e) {

        validationInfo.add("An exception occurred during the CRL retrieval process: " + e.getMessage());
    }

    public void infoTheCertNotValidYet(final Date validationDate, final Date notAfter, final Date notBefore) {

        final String endDate = DSSUtils.formatInternal(notAfter);
        final String startDate = DSSUtils.formatInternal(notBefore);
        final String valDate = DSSUtils.formatInternal(validationDate);
        validationInfo.add("The certificate is not valid yet! [" + startDate + "-" + endDate + "] on " + valDate);
    }

    public void infoTheCertIsExpired(final Date validationDate, final Date notAfter, final Date notBefore) {

        final String endDate = DSSUtils.formatInternal(notAfter);
        final String startDate = DSSUtils.formatInternal(notBefore);
        final String valDate = DSSUtils.formatInternal(validationDate);
        validationInfo.add("The certificate is expired! [" + startDate + "-" + endDate + "] on " + valDate);
    }

}
