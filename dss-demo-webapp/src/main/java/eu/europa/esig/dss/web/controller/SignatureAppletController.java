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
package eu.europa.esig.dss.web.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.web.dao.PreferencesDao;
import eu.europa.esig.dss.web.model.Preference;
import eu.europa.esig.dss.web.model.PreferenceKey;

/**
 *
 * Signature controller
 *
 * With this controller all configurations are in the applet. The applet only calls two webservices (getDataToSign / signDocument)
 *
 */
@Controller
@RequestMapping(value = "/signature-applet")
public class SignatureAppletController {

	/**
	 * @see PreferencesDao
	 */
	@Autowired
	private PreferencesDao preferencesDao;

	/**
	 * @param model The model attributes
	 * @return a view name
	 */
	@RequestMapping(method = RequestMethod.GET)
	public String showSignature(Model model, HttpServletRequest request) {
		Preference serviceUrl = preferencesDao.get(PreferenceKey.SERVICE_URL);
		model.addAttribute("prefUrlService", serviceUrl);
		Preference policyUrl = preferencesDao.get(PreferenceKey.DEFAULT_POLICY_URL);
		model.addAttribute("prefDefaultPolicyUrl", policyUrl);
		return "signature-applet";
	}

}
