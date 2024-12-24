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

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to find and load a corresponding implementation of
 * {@code eu.europa.esig.dss.asic.common.extractor.ASiCContainerExtractor} for the given
 * {@code eu.europa.esig.dss.model.DSSDocument} ASiC archive
 *
 */
public interface ASiCContainerExtractorFactory {

    /**
     * Returns whether the format of given ASiC document is supported by the current {@code ASiCContainerExtractor}
     *
     * @param asicContainer {@link DSSDocument}, which content should be extracted
     * @return TRUE if the document is supported by the current implementation, FALSE otherwise
     */
    boolean isSupported(DSSDocument asicContainer);

    /**
     * Creates a new {@code ASiCContainerExtractor} for the given ZIP-archive container
     *
     * @param asicContainer {@link DSSDocument}, representing a ZIP-containers to be extracted
     * @return {@link ASiCContainerExtractor} to be used to extract content of the ASiC container
     */
    ASiCContainerExtractor create(DSSDocument asicContainer);

}
