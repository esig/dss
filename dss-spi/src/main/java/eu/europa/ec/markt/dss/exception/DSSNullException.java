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
package eu.europa.ec.markt.dss.exception;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * This class is used when a null object is detected.
 *
 *
 *
 *
 *
 *
 */
public class DSSNullException extends DSSException {

    /**
     * This constructor creates an exception with the name of the parameter's class.
     *
     * @param parameter the null object
     */
    public DSSNullException(final Class<?> parameter) {

        super("Parameter: " + parameter.getName() + " cannot be null.");
    }

    /**
     * This constructor creates an exception with the name of the parameter's class and the name of the parameter. This constructor can be used when
     * the class of the parameter doesn't allow to unambiguously identify the parameter.
     *
     * @param javaClass the null object class
     * @param name      the name of the null object
     */
    public DSSNullException(final Class<?> javaClass, final String name) {

        super("Parameter with name: " + name + "[" + javaClass.getName() + "] cannot be null.");
    }

    public DSSNullException(final Class<?> javaClass, final String name, final String message) {

        super("Parameter:" + (DSSUtils.isNotBlank(name) ? (" " + name) : "") + "[" + javaClass.getName() + "] cannot be null. " + message);
    }
}
