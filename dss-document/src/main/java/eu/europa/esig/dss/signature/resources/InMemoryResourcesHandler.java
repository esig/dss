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
package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * This class represents an in-memory implementation of {@code DSSResourcesFactory}.
 * Using this class, all the objects handling during document signing will be stored in memory.
 *
 * NOTE: this class is used as a default implementation in DSS
 */
public class InMemoryResourcesHandler extends AbstractResourcesHandler {

    /**
     * Default constructor
     *
     */
    public InMemoryResourcesHandler() {
        // empty
    }

    @Override
    protected ByteArrayOutputStream buildOutputStream() {
        return new ByteArrayOutputStream();
    }

    @Override
    public DSSDocument writeToDSSDocument() throws IOException {
        try (OutputStream os = getOutputStream()) {
            if (!(os instanceof ByteArrayOutputStream)) {
                throw new IllegalStateException("The OutputStream shall be an implementation of ByteArrayOutputStream class!");
            }
            return new InMemoryDocument(((ByteArrayOutputStream) os).toByteArray());
        }
    }

}
