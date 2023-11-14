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
package eu.europa.esig.dss.token;

import java.security.PrivateKey;

/**
 * Provides an interface to a token connection with an exposed (accessible) private key entry.
 * NOTE: That does not mean that the cryptographic private key can be extracted.
 * The interface is meant to only provide direct access to the private key.
 * It is up to the underlying implementation to determine a way the private key can be accessed.
 */
public interface DSSPrivateKeyAccessEntry extends DSSPrivateKeyEntry {

    /**
     * Gets the private key
     *
     * @return the private key
     */
    PrivateKey getPrivateKey();

}
