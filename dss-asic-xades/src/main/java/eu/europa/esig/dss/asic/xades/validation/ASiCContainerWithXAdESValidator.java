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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is an implementation to validate ASiC containers with XAdES signature(s)
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class ASiCContainerWithXAdESValidator extends AbstractASiCContainerValidator {

    /**
     * The empty constructor
     */
    ASiCContainerWithXAdESValidator() {
        super(new ASiCContainerWithXAdESAnalyzer());
    }

    /**
     * The default constructor
     *
     * @param asicContainer {@link DSSDocument} to be validated
     */
    public ASiCContainerWithXAdESValidator(final DSSDocument asicContainer) {
        super(new ASiCContainerWithXAdESAnalyzer(asicContainer));
    }

    /**
     * The constructor from {@code ASiCContent}
     *
     * @param asicContent {@link ASiCContent} to be validated
     */
    public ASiCContainerWithXAdESValidator(final ASiCContent asicContent) {
        super(new ASiCContainerWithXAdESAnalyzer(asicContent));
    }

    @Override
    public ASiCContainerWithXAdESAnalyzer getDocumentAnalyzer() {
        return (ASiCContainerWithXAdESAnalyzer) super.getDocumentAnalyzer();
    }

}