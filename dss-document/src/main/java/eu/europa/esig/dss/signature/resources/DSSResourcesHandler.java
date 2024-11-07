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

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;

/**
 * This class is used to create objects required for a document signing process
 * (e.g. temporary OutputStream, returned DSSDocument, etc.).
 *
 */
public interface DSSResourcesHandler extends Closeable {

    /**
     * This method creates a new {@code OutputStream} to be used as an output for
     * a temporary signature document
     *
     * @return {@link OutputStream}
     * @throws IOException if an exception occurs during OutputStream creation
     */
    OutputStream createOutputStream() throws IOException;

    /**
     * This method creates a new {@code DSSDocument} representing a signed document,
     * based on the created {@code OutputStream}.
     *
     * @return {@link DSSDocument}
     * @throws IOException if an exception occurs during DSSDocument creation
     */
    DSSDocument writeToDSSDocument() throws IOException;

}
