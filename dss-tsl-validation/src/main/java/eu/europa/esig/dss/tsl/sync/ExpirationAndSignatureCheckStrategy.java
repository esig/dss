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
package eu.europa.esig.dss.tsl.sync;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;

import java.util.Date;

/**
 * Allows skipping expired or invalid trusted lists
 *
 */
public class ExpirationAndSignatureCheckStrategy implements SynchronizationStrategy {

	/**
	 * Define if expired trusted lists (next update after current time) are
	 * supported
	 */
	private boolean acceptExpiredTrustedList = false;

	/**
	 * Define if trusted lists with invalid or indeterminate signatures are
	 * supported
	 */
	private boolean acceptInvalidTrustedList = false;

	/**
	 * Define if expired list of trusted lists (next update after current time) are
	 * supported
	 */
	private boolean acceptExpiredListOfTrustedLists = false;

	/**
	 * Define if list of trusted lists with invalid or indeterminate signatures are
	 * supported
	 */
	private boolean acceptInvalidListOfTrustedLists = false;

	/**
	 * Sets if expired trusted lists are supported (next update after current time)
	 * 
	 * @param acceptExpiredTrustedList
	 *                                 true/false if expired trusted lists can be
	 *                                 synchronized
	 */
	public void setAcceptExpiredTrustedList(boolean acceptExpiredTrustedList) {
		this.acceptExpiredTrustedList = acceptExpiredTrustedList;
	}

	/**
	 * Sets if invalid trusted lists are supported (signature with FAILED or
	 * INDETERMINATE Indication)
	 * 
	 * @param acceptInvalidTrustedList
	 *                                 true/false if invalid trusted lists can be
	 *                                 synchronized
	 */
	public void setAcceptInvalidTrustedList(boolean acceptInvalidTrustedList) {
		this.acceptInvalidTrustedList = acceptInvalidTrustedList;
	}

	/**
	 * Sets if expired list of trusted lists and their TLs are supported (next
	 * update after current time)
	 * 
	 * @param acceptExpiredListOfTrustedLists
	 *                                        true/false if expired list of trusted
	 *                                        lists can be synchronized
	 */
	public void setAcceptExpiredListOfTrustedLists(boolean acceptExpiredListOfTrustedLists) {
		this.acceptExpiredListOfTrustedLists = acceptExpiredListOfTrustedLists;
	}

	/**
	 * Sets if invalid list of trusted lists and their TLs are supported (signature
	 * with FAILED or INDETERMINATE Indication)
	 * 
	 * @param acceptInvalidListOfTrustedLists
	 *                                        true/false if invalid list of trusted
	 *                                        lists can be synchronized
	 */
	public void setAcceptInvalidListOfTrustedLists(boolean acceptInvalidListOfTrustedLists) {
		this.acceptInvalidListOfTrustedLists = acceptInvalidListOfTrustedLists;
	}

	@Override
	public boolean canBeSynchronized(TLInfo trustedList) {
		return isSyncSupported(trustedList, acceptExpiredTrustedList, acceptInvalidTrustedList);
	}

	@Override
	public boolean canBeSynchronized(LOTLInfo listOfTrustedList) {
		return isSyncSupported(listOfTrustedList, acceptExpiredListOfTrustedLists, acceptInvalidListOfTrustedLists);
	}

	private boolean isSyncSupported(TLInfo tlInfo, boolean syncExpired, boolean syncInvalid) {

		if (!syncExpired) {
			ParsingInfoRecord parsingCacheInfo = tlInfo.getParsingCacheInfo();
			if (parsingCacheInfo.isResultExist()) {
				Date currentDate = new Date();
				Date nextUpdateDate = parsingCacheInfo.getNextUpdateDate();
				if (nextUpdateDate == null || currentDate.after(nextUpdateDate)) {
					return false;
				}
			}
		}

		if (!syncInvalid) {
			ValidationInfoRecord validationCacheInfo = tlInfo.getValidationCacheInfo();
			if (validationCacheInfo.isResultExist()) {
				return validationCacheInfo.isValid();
			}
		}

		return true;
	}

}
