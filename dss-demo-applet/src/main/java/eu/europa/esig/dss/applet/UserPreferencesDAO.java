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
package eu.europa.esig.dss.applet;

/**
 * Abstraction used to retrieve preferences from user.
 * 
 *
 *
 */

public interface UserPreferencesDAO {

    /**
     * Set the user PKCS11 library path
     * 
     * @param path
     */
    void setPKCS11LibraryPath(String path);

    /**
     * Get the user PKCS11 library path
     * 
     * @return
     */
    String getPKCS11LibraryPath();

    /**
     * Set the user SignatureTokenType
     * 
     * @param type
     */
    void setSignatureTokenType(SignatureTokenType type);

    /**
     * Get the user SignatureTokenType
     * 
     * @return
     */
    SignatureTokenType getSignatureTokenType();

    /**
     * Set the user PKCS12 file path
     * 
     * @param path
     */
    void setPKCS12FilePath(String path);

    /**
     * Get the user PKCS12 file path
     * 
     * @return
     */
    String getPKCS12FilePath();
}