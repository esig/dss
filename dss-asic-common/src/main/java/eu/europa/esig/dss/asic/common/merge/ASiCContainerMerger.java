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
 * This class is used to verify a possibility to merge ASiC containers and
 * merge them in a single container, when possible.
 *
 */
public interface ASiCContainerMerger {

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param containers {@link DSSDocument}s to be merged
     * @return TRUE if all documents are supported by the current container, FALSE otherwise
     */
    boolean isSupported(DSSDocument... containers);

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param asicContents {@link ASiCContent}s to be merged
     * @return TRUE if all containers are supported by the current container, FALSE otherwise
     */
    boolean isSupported(ASiCContent... asicContents);

    /**
     * Merges given containers to a new container document, when possible
     *
     * @return {@link DSSDocument} representing a merge result of the given ZIP-containers
     */
    DSSDocument merge();

    /**
     * Merges given containers to a single {@code ASiCContent}, when possible
     *
     * @return {@link ASiCContent} representing a merge result
     */
    ASiCContent mergeToASiCContent();

}
