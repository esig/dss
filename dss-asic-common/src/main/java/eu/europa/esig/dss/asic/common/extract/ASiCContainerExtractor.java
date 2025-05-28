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
package eu.europa.esig.dss.asic.common.extract;

import eu.europa.esig.dss.asic.common.ASiCContent;

/**
 * Extracts documents from a provided ZIP archive and produces a {@code eu.europa.esig.dss.asic.common.ASiCContent},
 * containing the representation of the archive's content
 *
 */
public interface ASiCContainerExtractor {

    /**
     * Extracts a content (documents) embedded into the {@code asicContainer}
     *
     * @return {@link ASiCContent}
     */
    ASiCContent extract();

    /**
     * Verifies whether the container format is supported by the current implementation
     *
     * @return TRUE if the container format is valid and supported, FALSE otherwise
     */
    boolean isSupportedContainerFormat();

}
