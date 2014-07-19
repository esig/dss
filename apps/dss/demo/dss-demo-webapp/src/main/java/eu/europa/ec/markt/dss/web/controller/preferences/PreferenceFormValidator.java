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

import java.net.URL;

import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.model.PreferenceKey;
import eu.europa.ec.markt.dss.web.model.PreferenceForm;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
@Component
public class PreferenceFormValidator implements Validator {
    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.equals(PreferenceForm.class);
    }

    @Override
    public void validate(Object target, Errors errors) {
        PreferenceForm preferenceForm = (PreferenceForm) target;
        if (preferenceForm.getKey().equals(PreferenceKey.DEFAULT_POLICY_URL.toString())) {
            // check that the entered URL is loadable
            final String value = preferenceForm.getValue();
            if (DSSUtils.isNotBlank(value)) {
                try {
                    DSSUtils.toString(new URL(value).openStream());
                } catch (Exception e) {
                    errors.rejectValue("value", "url.error");
                }
            }
        }
    }
}
