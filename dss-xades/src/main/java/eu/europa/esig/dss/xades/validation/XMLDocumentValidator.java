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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import org.w3c.dom.Document;

import java.util.List;

/**
 * Validator of XML Signed document
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class XMLDocumentValidator extends SignedDocumentValidator {

    /**
     * Default constructor
     */
    XMLDocumentValidator() {
        super(new XMLDocumentAnalyzer());
    }

    /**
     * The default constructor for XMLDocumentValidator. The created instance is
     * initialised with default {@code XAdESPaths} .
     *
     * @param dssDocument
     *                    The instance of {@code DSSDocument} to validate
     */
    public XMLDocumentValidator(final DSSDocument dssDocument) {
        super(new XMLDocumentAnalyzer(dssDocument));
    }

    @Override
    public XMLDocumentAnalyzer getDocumentAnalyzer() {
        return (XMLDocumentAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * NOT RECOMMENDED : This parameter allows disabling protection against XML
     * Signature wrapping attacks (XSW). It disables the research by XPath
     * expression for defined Type attributes.
     *
     * @param disableXSWProtection
     *                             true to disable the protection
     */
    public void setDisableXSWProtection(boolean disableXSWProtection) {
        getDocumentAnalyzer().setDisableXSWProtection(disableXSWProtection);
    }

    /**
     * This getter returns the {@code XAdESPaths}
     *
     * @return a list of {@link XAdESPath}
     */
    public List<XAdESPath> getXAdESPathsHolder() {
        return getDocumentAnalyzer().getXAdESPathsHolder();
    }

    /**
     * This adds a {@code XAdESPaths}. This is useful when the signature follows a
     * particular schema.
     *
     * @param xadesPathsHolder {@link XAdESPath}
     */
    public void addXAdESPathsHolder(final XAdESPath xadesPathsHolder) {
        getDocumentAnalyzer().addXAdESPathsHolder(xadesPathsHolder);
    }

    /**
     * Removes all elements from the list of query holders. The list will be empty after this call returns.
     */
    public void clearQueryHolders() {
        getDocumentAnalyzer().clearQueryHolders();
    }

    /**
     * Returns the root element of the validating document
     *
     * @return {@link Document}
     */
    public Document getRootElement() {
        return getDocumentAnalyzer().getRootElement();
    }

}