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
package eu.europa.ec.markt.dss.validation102853.rules;

public interface ExceptionMessage {

    public static final String EXCEPTION_TCOPPNTBI = "To carry out %s process the '%s' parameter need to be initialised!";
    public static final String EXCEPTION_TWUEIVP = "There was an unexpected error in the validation process!";
    public static final String EXCEPTION_TPTCBN = "The timestamp production time cannot be null!";
    public static final String EXCEPTION_CTVSBIOO = "The current-time variable should be initialised only once!";

    public static final String EXCEPTION_ = "The '%s' parameter cann!";

}
