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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.bouncycastle.cms.CMSSignedData;

/**
 * Validation of CMS document
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class CMSDocumentValidator extends SignedDocumentValidator {

    /** The CMSSignedData to be validated */
    protected CMSSignedData cmsSignedData;

    /**
     * Default constructor
     */
    CMSDocumentValidator() {
        super(new CMSDocumentAnalyzer());
    }

    /**
     * The default constructor for {@code CMSDocumentValidator}.
     *
     * @param cmsSignedData
     *            pkcs7-signature(s)
     */
    public CMSDocumentValidator(final CMSSignedData cmsSignedData) {
        super(new CMSDocumentAnalyzer(cmsSignedData));
    }

    /**
     * The default constructor for {@code CMSDocumentValidator}.
     *
     * @param document
     *            document to validate (with the signature(s))
     */
    public CMSDocumentValidator(final DSSDocument document) {
        super(new CMSDocumentAnalyzer(document));
    }

    @Override
    public CMSDocumentAnalyzer getDocumentAnalyzer() {
        return (CMSDocumentAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * This method returns a CMSSignedData
     *
     * @return {@link CMSSignedData}
     */
    public CMSSignedData getCmsSignedData() {
        return getDocumentAnalyzer().getCmsSignedData();
    }

    @Override
    protected CAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        return new CAdESDiagnosticDataBuilder();
    }

}