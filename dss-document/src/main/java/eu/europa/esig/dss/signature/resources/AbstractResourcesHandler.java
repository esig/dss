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
package eu.europa.esig.dss.signature.resources;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Abstract class used to create OutputStream to be used across DSS code
 *
 */
public abstract class AbstractResourcesHandler implements DSSResourcesHandler {

    /** OutputStream instance */
    private OutputStream os;

    @Override
    public OutputStream createOutputStream() throws IOException {
        if (os != null) {
            throw new IllegalStateException("Cannot create OutputStream! The OutputStream has been already created!");
        }
        this.os = buildOutputStream();
        return os;
    }

    /**
     * Builds {@code OutputStream}
     *
     * @return {@link OutputStream}
     * @throws IOException if an error occurs while building OutputStream
     */
    protected abstract OutputStream buildOutputStream() throws IOException;

    /**
     * This method returns the internal OutputStream instance
     *
     * @return {@link OutputStream}
     */
    protected OutputStream getOutputStream() {
        if (os == null) {
            throw new IllegalStateException("Method #createOutputStream() shall be called before!");
        }
        return os;
    }

    @Override
    public void close() throws IOException {
        if (os != null) {
            os.close();
        }
    }

}
