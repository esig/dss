/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.validation102853.crl.CRLSource;
import eu.europa.ec.markt.dss.validation102853.crl.CRLToken;

/**
 * Verifier based on CRL
 *
 * @version $Revision: 1757 $ - $Date: 2013-03-14 20:33:28 +0100 (Thu, 14 Mar 2013) $
 */

public class CRLCertificateVerifier implements CertificateStatusVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(CRLCertificateVerifier.class);

    private final CRLSource crlSource;

    /**
     * Main constructor.
     *
     * @param crlSource the CRL repository used by this CRL trust linker.
     */
    public CRLCertificateVerifier(final CRLSource crlSource) {

        this.crlSource = crlSource;
    }

    @Override
    public RevocationToken check(final CertificateToken certificateToken) {

        try {

            if (crlSource == null) {

                certificateToken.extraInfo().infoCRLSourceIsNull();
                return null;
            }
            final CRLToken crlToken = crlSource.findCrl(certificateToken);
            if (crlToken == null) {

                if (LOG.isInfoEnabled()) {
                    LOG.info("No CRL found for: " + certificateToken.getDSSIdAsString());
                }
                return null;
            }
            if (!crlToken.isValid()) {

                LOG.warn("The CRL is not valid !");
                certificateToken.extraInfo().infoCRLIsNotValid();
                return null;
            }
            certificateToken.setRevocationToken(crlToken);
            return crlToken;
        } catch (final Exception e) {

            LOG.error("Exception when accessing CRL for " + certificateToken.getDSSIdAsString(), e);
            certificateToken.extraInfo().infoCRLException(e);
            return null;
        }
    }
}
