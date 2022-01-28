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
package eu.europa.esig.dss.enumerations;

/**
 * A name which, in conjunction with Fields, indicates the set of fields that should be locked.
 *
 */
public enum PdfLockAction {

    /** All form fields do not permit changes */
    ALL("All"),

    /** Only those form fields specified in fields do not permit changes */
    INCLUDE("Include"),

    /** Only those form fields not specified in fields do not permit changes */
    EXCLUDE("Exclude");

    /** The value of the /Action field */
    private String name;

    /**
     * Default constructor
     *
     * @param name {@link String} value of the field
     */
    PdfLockAction(String name) {
        this.name = name;
    }

    /**
     * Returns name value of the field parameter
     *
     * @return {@link String}
     */
    public String getName() {
        return name;
    }

    /**
     * Returns a {@code Action} corresponding to the given {@code name}
     *
     * @param name {@link String}
     * @return {@link PdfLockAction}
     */
    public static PdfLockAction forName(String name) {
        for (PdfLockAction action : values()) {
            if (name.equals(action.getName())) {
                return action;
            }
        }
        throw new IllegalArgumentException(String.format("Unsupported /Action field value : %s", name));
    }

}
