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
package eu.europa.esig.dss.asic.xades.extract;

import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractorFactory;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESAnalyzerFactory;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Objects;

/**
 * This class is used to load a corresponding {@code eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger}
 * for an ASiC with XAdES container
 *
 */
public class ASiCWithXAdESContainerExtractorFactory implements ASiCContainerExtractorFactory {

    /**
     * Default constructor
     */
    public ASiCWithXAdESContainerExtractorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument asicContainer) {
        Objects.requireNonNull(asicContainer, "ASiC container cannot be null!");

        final ASiCContainerWithXAdESAnalyzerFactory documentValidatorFactory = new ASiCContainerWithXAdESAnalyzerFactory();
        return documentValidatorFactory.isSupported(asicContainer);
    }

    @Override
    public ASiCContainerExtractor create(DSSDocument asicContainer) {
        Objects.requireNonNull(asicContainer, "ASiC container cannot be null!");
        if (!isSupported(asicContainer)) {
            throw new UnsupportedOperationException(
                    "The ASiC container is not supported by ASiC with XAdES container extractor factory!");
        }
        return new ASiCWithXAdESContainerExtractor(asicContainer);
    }

}
