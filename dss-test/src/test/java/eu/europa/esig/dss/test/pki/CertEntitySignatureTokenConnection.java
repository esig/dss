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
package eu.europa.esig.dss.test.pki;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.Collections;
import java.util.List;

/**
 * Represents a connection to a {@code eu.europa.esig.dss.pki.model.CertEntity} for signing using its private key connection
 *
 */
public class CertEntitySignatureTokenConnection extends AbstractSignatureTokenConnection {

    /** The PKI CertEntity used on signing */
    private final CertEntity certEntity;

    /**
     * Default constructor
     *
     * @param certEntity {@link CertEntity}
     */
    public CertEntitySignatureTokenConnection(final CertEntity certEntity) {
        this.certEntity = certEntity;
    }

    @Override
    public void close() {
        // not required
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
        return Collections.singletonList(new CertEntityKeyEntry(certEntity));
    }

}
