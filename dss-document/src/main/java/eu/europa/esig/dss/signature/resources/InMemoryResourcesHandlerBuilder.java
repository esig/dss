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

import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;

/**
 * This class creates an {@code InMemoryResourcesHandler} to create in-memory objects
 *
 * NOTE: This implementation is used by default
 */
public class InMemoryResourcesHandlerBuilder implements DSSResourcesHandlerBuilder {

    /**
     * Default constructor
     */
    public InMemoryResourcesHandlerBuilder() {
        // empty
    }

    @Override
    public InMemoryResourcesHandler createResourcesHandler() {
        return new InMemoryResourcesHandler();
    }

}
