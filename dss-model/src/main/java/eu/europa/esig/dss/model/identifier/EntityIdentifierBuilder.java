/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.identifier;

import eu.europa.esig.dss.model.DSSException;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;

/**
 * Builds a {@code eu.europa.esig.dss.model.identifier.EntityIdentifier} for
 * the given {@code java.security.PublicKey} and {@code javax.security.auth.x500.X500Principal} pair
 *
 */
public class EntityIdentifierBuilder implements IdentifierBuilder {

    /** Public key */
    private final PublicKey publicKey;

    /** Subject name */
    private final X500Principal subjectName;

    /**
     * Default constructor
     *
     * @param publicKey {@link PublicKey}
     * @param subjectName {@link X500Principal}
     */
    public EntityIdentifierBuilder(final PublicKey publicKey, final X500Principal subjectName) {
        this.publicKey = publicKey;
        this.subjectName = subjectName;
    }

    @Override
    public EntityIdentifier build() {
        return new EntityIdentifier(buildBinaries());
    }

    /**
     * Builds unique binary data describing the signature object
     *
     * @return a byte array
     */
    protected byte[] buildBinaries() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            if (publicKey != null) {
                baos.write(publicKey.getEncoded());
            }
            if (subjectName != null) {
                baos.write(subjectName.getEncoded());
            }
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("An error occurred while building an Identifier : %s", e.getMessage()), e);
        }
    }

}
