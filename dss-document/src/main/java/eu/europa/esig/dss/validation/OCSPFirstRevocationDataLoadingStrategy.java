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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class fetches firstly OCSP token response, if not available, tries CRL and returns the first succeeded result
 *
 * NOTE: This implementation is use by default for revocation retrieving
 *
 */
public class OCSPFirstRevocationDataLoadingStrategy extends RevocationDataLoadingStrategy {

    private static final Logger LOG = LoggerFactory.getLogger(OCSPFirstRevocationDataLoadingStrategy.class);

    @Override
    @SuppressWarnings("rawtypes")
    public RevocationToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {
        RevocationToken<?> result = checkOCSP(certificateToken, issuerToken);
        if (result != null) {
            return result;
        }
        result = checkCRL(certificateToken, issuerToken);
        if (result != null) {
            return result;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("There is no response for {} neither from OCSP nor from CRL!", certificateToken.getDSSIdAsString());
        }
        return null;
    }

}
