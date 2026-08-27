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
package eu.europa.esig.dss.validation.job.dto;

import eu.europa.esig.dss.model.job.ParsingInfoRecord;

import java.util.List;

/**
 * The parsing record DTO
 */
public abstract class AbstractParsingCacheDTO extends AbstractCacheDTO implements ParsingInfoRecord {
	
	private static final long serialVersionUID = 5464908480606825440L;

	/** A list of error messages occurred during a structure validation */
	protected List<String> structureValidationMessages;

	/**
	 * Default constructor
	 */
	protected AbstractParsingCacheDTO() {
		// empty
	}

	/**
	 * Copies the cache DTO
	 *
	 * @param cacheDTO {@link AbstractCacheDTO}
	 */
	protected AbstractParsingCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}

	@Override
	public List<String> getStructureValidationMessages() {
		return structureValidationMessages;
	}

	/**
	 * Sets the structure validation error messages
	 *
	 * @param structureValidationMessages a list of {@link String} error messages when occurred on the structure validation
	 */
	public void setStructureValidationMessages(List<String> structureValidationMessages) {
		this.structureValidationMessages = structureValidationMessages;
	}

}
