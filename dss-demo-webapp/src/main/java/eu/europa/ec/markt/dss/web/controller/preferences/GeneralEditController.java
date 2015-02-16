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

import eu.europa.ec.markt.dss.dao.PreferencesDao;
import eu.europa.ec.markt.dss.model.Preference;
import eu.europa.ec.markt.dss.model.PreferenceKey;
import eu.europa.ec.markt.dss.web.model.PreferenceForm;

/**
 *
 * General edit controller
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
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
