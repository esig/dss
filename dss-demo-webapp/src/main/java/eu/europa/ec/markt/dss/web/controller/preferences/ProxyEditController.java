/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.web.controller.preferences;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.WebRequest;

import eu.europa.ec.markt.dss.dao.ProxyKey;
import eu.europa.ec.markt.dss.dao.ProxyPreference;
import eu.europa.ec.markt.dss.manager.ProxyPreferenceManager;
import eu.europa.ec.markt.dss.web.model.PreferenceForm;

/**
 * TODO
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
@Controller
@RequestMapping(value = "/admin/proxy")
public class ProxyEditController {

	private static final Logger LOG = LoggerFactory.getLogger(ProxyEditController.class);

	@Autowired
	private ProxyPreferenceManager proxyPreferenceManager;

	/**
	 * @param webRequest The web request
	 * @return a proxy form bean
	 */
	@ModelAttribute("preferenceForm")
	public final PreferenceForm setupForm(final WebRequest webRequest) {

		final String requestKey = webRequest.getParameter("key");
		//		System.out.println("#requestKey: " + requestKey);
		final PreferenceForm form = new PreferenceForm();
		final ProxyKey proxyKey = ProxyKey.fromKey(requestKey);
		//		System.out.println("proxyKey: " + proxyKey);
		final ProxyPreference preference = proxyPreferenceManager.get(proxyKey);

		form.setKey(preference.getProxyKey().getKeyName());
		form.setValue(preference.getValue());

		return form;
	}

	/**
	 * @param model The view model
	 * @return a view name
	 */
	@RequestMapping(value = "/edit", method = RequestMethod.GET)
	public String showForm(final Model model) {

		return "admin-proxy-edit";
	}

	/**
	 * @param form The proxy form bean
	 * @return a view name
	 */
	@RequestMapping(value = "/edit", method = RequestMethod.POST)
	public String updatePreferences(@ModelAttribute("preferenceForm") final PreferenceForm form) {

		final String proxyKeyString = form.getKey();
		final String proxyValueString = form.getValue();
		proxyPreferenceManager.update(proxyKeyString, proxyValueString);
		LOG.trace(">>> Proxy preference updated: " + proxyKeyString + "(" + proxyValueString + ")/" + proxyPreferenceManager);
		return "redirect:/admin/proxy";
	}
}
