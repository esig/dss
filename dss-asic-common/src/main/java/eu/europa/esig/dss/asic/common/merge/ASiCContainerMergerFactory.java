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
package eu.europa.esig.dss.asic.common.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to load relevant {@code eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger}
 * for given {@code eu.europa.esig.dss.model.DSSDocument} containers or
 * {@code eu.europa.esig.dss.asic.common.ASiCContent}s
 *
 */
public interface ASiCContainerMergerFactory {

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param containers {@link DSSDocument}s to be merged
     * @return TRUE if both documents are supported by the current container, FALSE otherwise
     */
    boolean isSupported(DSSDocument... containers);

    /**
     * Creates a new {@code ASiCContainerMerger} for the given ZIP-archive containers
     *
     * @param containers {@link DSSDocument}s representing ZIP-containers to be merged
     * @return {@link DSSDocument} representing a merge result of given ZIP-containers
     */
    ASiCContainerMerger create(DSSDocument... containers);

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param asicContents {@link ASiCContent}s to be merged
     * @return TRUE if both containers are supported by the current container, FALSE otherwise
     */
    boolean isSupported(ASiCContent... asicContents);

    /**
     * Creates a new {@code ASiCContainerMerger} for the given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s representing content of ZIP-containers to be merged
     * @return {@link ASiCContent} representing a merge result
     */
    ASiCContainerMerger create(ASiCContent... asicContents);

}
