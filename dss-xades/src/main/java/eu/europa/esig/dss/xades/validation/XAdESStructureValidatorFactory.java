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
package eu.europa.esig.dss.xades.validation;

/**
 * Creates a relevant implementation of {@code XAdESStructureValidator}.
 * This class also evaluates a presence of 'dss-validation' module in the classpath.
 *
 */
public class XAdESStructureValidatorFactory {

    /** Current factory instance */
    private static XAdESStructureValidatorFactory singleton;

    /**
     * Default constructor
     */
    protected XAdESStructureValidatorFactory() {
        // empty
    }

    /**
     * Gets the instance of {@code XAdESStructureValidatorFactory}
     *
     * @return {@link XAdESStructureValidatorFactory}
     */
    public static XAdESStructureValidatorFactory getInstance() {
        if (singleton == null) {
            singleton = new XAdESStructureValidatorFactory();
        }
        return singleton;
    }

    /**
     * Creates a {@code XAdESStructureValidator} for the given {@code XAdESSignature}
     *
     * @param signature {@link XAdESSignature} to validate structure of
     * @return {@link XAdESStructureValidator}
     */
    public XAdESStructureValidator fromXAdESSignature(XAdESSignature signature) {
        assertXAdESStructureValidatorLoaded();
        return new XAdESStructureValidator(signature.getSignatureElement(), signature.getXAdESPaths());
    }

    /**
     * Verifies whether the {@code XAdESStructureValidator} is available and 'dss-validation' module is successfully loaded
     */
    protected void assertXAdESStructureValidatorLoaded() {
        try {
            Class.forName("eu.europa.esig.dss.xades.validation.XAdESStructureValidator");
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            throw new ExceptionInInitializerError(
                    "No implementation found for XSD Utils in classpath, please include 'dss-validation' module for structure validation.");
        }
    }

}
