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
package eu.europa.esig.dss.lote.sync;

import eu.europa.esig.dss.model.job.ValidationInfoRecord;
import eu.europa.esig.dss.model.lote.LoLoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.record.LoTEParsingInfoRecord;
import eu.europa.esig.dss.validation.job.sync.SynchronizationStrategy;

import java.util.Date;

/**
 * Allows skipping expired or invalid LoTEs
 *
 */
public class LoTEExpirationAndSignatureCheckStrategy implements SynchronizationStrategy<LoTEInfo, LoLoTEInfo> {

	/**
	 * Define if expired lists (next update after current time) are supported
	 */
	private boolean acceptExpiredList = false;

	/**
	 * Define if lists with invalid or indeterminate signatures are supported
	 */
	private boolean acceptInvalidList = false;

	/**
	 * Define if expired lists of lists (next update after current time) are supported
	 */
	private boolean acceptExpiredListOfLists = false;

	/**
	 * Define if lists of lists with invalid or indeterminate signatures are supported
	 */
	private boolean acceptInvalidListOfLists = false;

	/**
	 * Default constructor instantiating object with null values
	 */
	public LoTEExpirationAndSignatureCheckStrategy() {
		// empty
	}

	/**
	 * Sets if expired lists are supported (next update after current time)
	 * 
	 * @param acceptExpiredList
	 *                                 true/false if expired lists can be synchronized
	 */
	public void setAcceptExpiredList(boolean acceptExpiredList) {
		this.acceptExpiredList = acceptExpiredList;
	}

	/**
	 * Sets if invalid lists are supported (signature with FAILED or
	 * INDETERMINATE Indication)
	 * 
	 * @param acceptInvalidList
	 *                                 true/false if invalid lists can be synchronized
	 */
	public void setAcceptInvalidList(boolean acceptInvalidList) {
		this.acceptInvalidList = acceptInvalidList;
	}

	/**
	 * Sets if expired lists of lists are supported (next update after current time)
	 *
	 * @param acceptExpiredListOfLists
	 *                                 true/false if expired lists of lists can be synchronized
	 */
	public void setAcceptExpiredListOfLists(boolean acceptExpiredListOfLists) {
		this.acceptExpiredListOfLists = acceptExpiredListOfLists;
	}

	/**
	 * Sets if invalid lists of lists are supported (signature with FAILED or
	 * INDETERMINATE Indication)
	 *
	 * @param acceptInvalidListOfLists
	 *                                 true/false if invalid lists of lists can be synchronized
	 */
	public void setAcceptInvalidListOfLists(boolean acceptInvalidListOfLists) {
		this.acceptInvalidListOfLists = acceptInvalidListOfLists;
	}

	@Override
	public boolean canBeSynchronized(LoTEInfo documentList) {
		return isSyncSupported(documentList, acceptExpiredList, acceptInvalidList);
	}

	@Override
	public boolean canBeSynchronized(LoLoTEInfo documentList) {
		return isSyncSupported(documentList, acceptExpiredListOfLists, acceptInvalidListOfLists);
	}

	private boolean isSyncSupported(LoTEInfo loteInfo, boolean syncExpired, boolean syncInvalid) {

		if (!syncExpired) {
			LoTEParsingInfoRecord parsingCacheInfo = loteInfo.getParsingCacheInfo();
			if (parsingCacheInfo == null || !parsingCacheInfo.isResultExist()) {
				return false;
			}
			Date currentDate = new Date();
			Date nextUpdateDate = parsingCacheInfo.getNextUpdateDate();
			if (nextUpdateDate == null || currentDate.after(nextUpdateDate)) {
				return false;
			}
		}

		if (!syncInvalid) {
			ValidationInfoRecord validationCacheInfo = loteInfo.getValidationCacheInfo();
			if (validationCacheInfo == null || !validationCacheInfo.isResultExist()) {
				return false;
			}
			return validationCacheInfo.isValid();
		}

		return true;
	}

}
