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
package eu.europa.esig.dss.web.controller.preferences;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.WebRequest;

import eu.europa.esig.dss.web.dao.PreferencesDao;
import eu.europa.esig.dss.web.model.Preference;
import eu.europa.esig.dss.web.model.PreferenceForm;
import eu.europa.esig.dss.web.model.PreferenceKey;

/**
 *
 * General edit controller
 *
 */
@Controller
@RequestMapping(value = "/admin/general")
public class GeneralEditController {

	/**
	 * @see PreferencesDao
	 */
	@Autowired
	private PreferencesDao preferencesDao;

	/**
	 *
	 * @param webRequest The web request
	 * @return a form bean
	 */
	@ModelAttribute("preferenceForm")
	public final PreferenceForm setupForm(final WebRequest webRequest) {

		final String requestKey = webRequest.getParameter("key");
		final PreferenceForm form = new PreferenceForm();
		final Preference preference = preferencesDao.get(PreferenceKey.fromKey(requestKey));
		form.setKey(preference.getKey());
		form.setValue(preference.getValue());

		return form;
	}

	/**
	 *
	 * @param model The model attributes
	 * @return a view name
	 */
	@RequestMapping(value = "/edit", method = RequestMethod.GET)
	public String showForm(final Model model) {
		return "admin-general-edit";
	}

	@Autowired
	private PreferenceFormValidator preferenceFormValidator;

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(preferenceFormValidator);
	}

	/**
	 *
	 * @param form a form bean
	 * @return a view name
	 */
	@RequestMapping(value = "/edit", method = RequestMethod.POST)
	public String updatePreferences(@ModelAttribute("preferenceForm") @Valid final PreferenceForm form, BindingResult bindingResult) {
		if (bindingResult.hasErrors()) {
			return "admin-general-edit";
		}
		Preference preference = new Preference();
		preference.setKey(form.getKey());
		preference.setValue(form.getValue());

		preferencesDao.update(preference);

		return "redirect:/admin/general";
	}

}
