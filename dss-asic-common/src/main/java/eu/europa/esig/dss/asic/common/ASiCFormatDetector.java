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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This interface contains method for verification of a document on a conformance to a ZIP or ASiC format
 * NOTE: sometimes it is required to accept simple ZIP archive, but reject ASiC container of a different
 *       implementation (i.e. XAdES vs CAdES), that is why we implement two methods.
 *
 */
public interface ASiCFormatDetector {

    /**
     * Verifies whether the {@code document} is a supported ZIP container by the current implementation
     *
     * @param document {@link DSSDocument} to be analyzed
     * @return TRUE if the document is a supported ZIP container, FALSE otherwise
     */
    boolean isSupportedZip(DSSDocument document);

    /**
     * Verifies whether the {@code document} is a supported ASiC container by the current implementation
     *
     * @param document {@link DSSDocument} to be analyzed
     * @return TRUE if the document is a supported ASiC container, FALSE otherwise
     */
    boolean isSupportedASiC(DSSDocument document);

    /**
     * Verifies whether the {@code asicContent} is a supported ZIP container by the current implementation
     *
     * @param asicContent {@link ASiCContent} to be analyzed
     * @return TRUE if the ASiCContent is a supported ZIP container, FALSE otherwise
     */
    boolean isSupportedZip(ASiCContent asicContent);

    /**
     * Verifies whether the {@code asicContent} is a supported ASiC container by the current implementation
     *
     * @param asicContent {@link ASiCContent} to be analyzed
     * @return TRUE if the ASiCContent is a supported ASiC container, FALSE otherwise
     */
    boolean isSupportedASiC(ASiCContent asicContent);

}
