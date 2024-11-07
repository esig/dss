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
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * Builds {@code ASiCContent} for an ASiC with CAdES container
 *
 */
public class ASiCWithXAdESASiCContentBuilder extends AbstractASiCContentBuilder {

    /**
     * Default constructor
     */
    public ASiCWithXAdESASiCContentBuilder() {
        // empty
    }

    @Override
    protected boolean isAcceptableContainerFormat(DSSDocument archiveDocument) {
        List<String> filenames = ZipUtils.getInstance().extractEntryNames(archiveDocument);
        return ASiCUtils.isAsicFileContent(filenames) ||
                (ASiCUtils.areFilesContainMimetype(filenames) && ASiCUtils.isContainerOpenDocument(archiveDocument));
    }

    @Override
    protected DefaultASiCContainerExtractor getContainerExtractor(DSSDocument archiveDocument) {
        return new ASiCWithXAdESContainerExtractor(archiveDocument);
    }

}
