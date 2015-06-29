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
package eu.europa.esig.dss.validation.policy.rules;

public interface ExceptionMessage {

	String EXCEPTION_TCOPPNTBI = "To carry out %s process the '%s' parameter need to be initialised!";
	String EXCEPTION_TWUEIVP = "There was an unexpected error in the validation process!";
	String EXCEPTION_TPTCBN = "The timestamp production time cannot be null!";
	String EXCEPTION_CTVSBIOO = "The current-time variable should be initialised only once!";

	String EXCEPTION_ = "The '%s' parameter cann!";

}
