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

package eu.europa.ec.markt.dss.signature.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 *
 * @version $Revision: 1835 $ - $Date: 2013-03-12 09:54:17 +0100 (Tue, 12 Mar 2013) $
 */

public abstract class AbstractSignatureTokenConnection implements SignatureTokenConnection {

    protected static final Logger LOG = LoggerFactory.getLogger(AbstractSignatureTokenConnection.class);

    protected static String getCauseMessage(final Exception e) {
        return (e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
    }

    @Override
    public byte[] sign(final byte[] bytes, final DigestAlgorithm digestAlgorithm, final DSSPrivateKeyEntry keyEntry) throws DSSException {

        final EncryptionAlgorithm encryptionAlgorithm = keyEntry.getEncryptionAlgorithm();
        LOG.info("Signature algorithm: " + encryptionAlgorithm + "/" + digestAlgorithm);
        final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
        final String javaSignatureAlgorithm = signatureAlgorithm.getJCEId();
        final byte[] encryptedBytes = DSSUtils.encrypt(javaSignatureAlgorithm, keyEntry.getPrivateKey(), bytes);
        return encryptedBytes;
    }
}