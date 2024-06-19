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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.validation.ASiCContainerDiagnosticDataBuilder;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is an implementation to validate ASiC containers with CAdES signature(s)
 *
 */
public class ASiCContainerWithCAdESValidator extends AbstractASiCContainerValidator {

    /**
     * The empty constructor
     */
    ASiCContainerWithCAdESValidator() {
        super(new ASiCContainerWithCAdESAnalyzer());
    }

    /**
     * The default constructor
     *
     * @param asicContainer {@link DSSDocument} to be validated
     */
    public ASiCContainerWithCAdESValidator(final DSSDocument asicContainer) {
        super(new ASiCContainerWithCAdESAnalyzer(asicContainer));
    }

    /**
     * The constructor with {@link ASiCContent}
     *
     * @param asicContent {@link ASiCContent} to be validated
     */
    public ASiCContainerWithCAdESValidator(final ASiCContent asicContent) {
        super(new ASiCContainerWithCAdESAnalyzer(asicContent));
    }

    @Override
    public ASiCContainerWithCAdESAnalyzer getDocumentAnalyzer() {
        return (ASiCContainerWithCAdESAnalyzer) super.getDocumentAnalyzer();
    }

    @Override
    protected ASiCContainerDiagnosticDataBuilder instantiateASiCDiagnosticDataBuilder() {
        return new ASiCWithCAdESDiagnosticDataBuilder();
    }

}